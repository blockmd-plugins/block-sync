#!/usr/bin/env python3
"""Official block-sync plugin for Block (blockmd)."""

import base64
from datetime import datetime
import errno
try:
    import fcntl
except ImportError:
    fcntl = None
import hashlib
import html
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


VALID_PROTOCOLS = ("local_mirror", "webdav", "git")
VALID_CONFLICT_POLICIES = ("keep_both", "remote_first", "local_first")
VALID_GIT_AUTHS = ("ssh", "token")
DELETE_GUARD_THRESHOLD = 5
MAX_LOG_ENTRIES = 20
CHINESE_TEXT = re.compile(r"[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]")
LOG_STATUS_EN = {
    "完成": "Complete",
    "成功": "Success",
    "通过": "Passed",
    "无变更": "No Changes",
    "待确认": "Confirmation Required",
    "失败": "Failed",
    "未连通": "Connection Failed",
    "已取消": "Canceled",
    "冲突副本": "Conflict Copy",
}
LAYOUTS_META_KEY = "notebook_layouts"

DEFAULT_CONFIG = {
    "selected_notebooks": [],
    "protocol": "local_mirror",
    "mirror_dir": "",
    "sync_scope": "all",
    "webdav_url": "",
    "webdav_dir": "/BlockNotes",
    "webdav_user": "",
    "webdav_pass": "",
    "git_remote": "",
    "git_branch": "main",
    "git_auth": "ssh",
    "git_token": "",
    "auto_sync": True,
    "sync_assets": True,
    "conflict_policy": "keep_both",
    "delete_guard": True,
}


class HostBridge:
    """Line-delimited JSON-RPC 2.0 bridge between plugin and Block host."""

    def __init__(self):
        self._seq = 1000

    def send(self, obj):
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    def notify_progress(self, done=None, total=None, progress=None, label=None):
        params = {}
        if done is not None:
            params["done"] = int(done)
        if total is not None:
            params["total"] = int(total)
        if progress is not None:
            params["progress"] = float(progress)
        if label:
            params["label"] = str(label)
        if not params:
            return
        try:
            self.send({"jsonrpc": "2.0", "method": "host.action.progress", "params": params})
        except Exception:
            pass

    def call_host(self, method, params=None):
        self._seq += 1
        req_id = f"p-{self._seq}"
        self.send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}})
        while True:
            line = sys.stdin.readline()
            if not line:
                raise RuntimeError("stdin closed while awaiting host response")
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            if str(msg.get("id")) == req_id:
                if msg.get("error"):
                    raise RuntimeError(msg["error"].get("message", "host error"))
                return msg.get("result", {})

    def serve(self, handler, localize_error):
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            req = json.loads(line)
            method = req.get("method")
            req_id = req.get("id")
            try:
                result = handler(self, method, req.get("params") or {})
                self.send({"jsonrpc": "2.0", "id": req_id, "result": result})
                if method == "plugin.shutdown":
                    break
            except Exception as exc:
                self.send({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": localize_error(str(exc))},
                })


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode("utf-8"))


def now_hms():
    return datetime.now().strftime("%H:%M:%S")


def format_hm(time_str):
    raw = str(time_str or "").strip()
    m = re.match(r"^(\d{1,2}:\d{2})(?::\d{2})?$", raw)
    return m.group(1) if m else raw


def conflict_stamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def is_safe_rel_path(rel_path):
    if not rel_path or "\x00" in rel_path or rel_path.startswith(("/", "\\")):
        return False
    norm = rel_path.replace("\\", "/")
    parts = norm.split("/")
    if any(part in ("", ".", "..") or part.startswith(".") for part in parts):
        return False
    return True


def is_safe_rel_md(rel_path):
    return is_safe_rel_path(rel_path) and os.path.splitext(rel_path)[1].lower() in {
        ".md", ".markdown", ".mdown", ".mkd", ".mkdn", ".mdwn", ".mdtxt", ".mdtext", ".mdx",
    }


def is_safe_rel_asset(rel_path):
    return "\\" not in rel_path and is_safe_rel_path(rel_path) and "assets" in rel_path.split("/")[:-1]


def sync_dir_key(name):
    return unicodedata.normalize("NFC", name).casefold()


def in_sync_subdir(rel_path, subdirs):
    return sync_dir_key(rel_path.split("/", 1)[0]) in subdirs


def note_asset_paths(note_path, text):
    # Block emits Markdown links/images and HTML src attributes for resized media.
    fence = ""
    visible = []
    for line in text.splitlines():
        marker = re.match(r"^\s*(\x60{3,}|~{3,})(.*)$", line)
        if fence:
            if marker and marker[1].startswith(fence) and not marker[2].strip():
                fence = ""
            visible.append("")
        elif marker:
            fence = marker[1]
            visible.append("")
        else:
            visible.append(re.sub(
                r"(\x60+)(?!\x60)(.+?)(?<!\x60)\1(?!\x60)",
                lambda span: " " * len(span[0]), line,
            ))
    text = "\n".join(visible)
    bare_dest = r"(?:\\.|[^\s()<>\\]|\((?:\\.|[^\s()<>\\])*\))+"
    link_dest = rf"<([^>\n]+)>|({bare_dest})"
    links = re.findall(rf"\]\(\s*(?:{link_dest})(?=[\s)])", text)
    refs = re.findall(
        rf"(?m)^ {{0,3}}\[(?:\\.|[^\]\\\n])+\]:[ \t]*(?:\r?\n[ \t]*)?(?:{link_dest})(?=[ \t\r]|$)",
        text,
    )
    attrs = re.findall(r"""(?is)\b(?:src|href)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""", text)
    note_dir = posixpath.dirname(note_path)
    paths = set()
    for dest in (*links, *refs, *attrs):
        value = html.unescape(next(part for part in dest if part))
        value = re.sub(r"\\([()<>])", r"\1", value)
        decoded = urllib.parse.unquote(value.split("#", 1)[0].split("?", 1)[0])
        for candidate in {value, decoded}:
            if candidate.startswith(("/", "\\")) or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", candidate):
                continue
            rel_path = posixpath.normpath(posixpath.join(note_dir, candidate))
            if is_safe_rel_asset(rel_path):
                paths.add(rel_path)
    return paths


def make_conflict_path(rel_path, stamp):
    norm = rel_path.replace("\\", "/")
    stem, extension = os.path.splitext(norm)
    return f"{stem}.conflict-{stamp}{extension or '.md'}"


def sanitize_error_text(exc):
    msg = str(exc).strip().replace("\n", " ")
    if len(msg) > 120:
        msg = msg[:117] + "..."
    return msg or exc.__class__.__name__


class SyncPlugin:
    def __init__(self):
        self.plugin_id = "block-sync"
        self.data_dir = ""
        self.downloads_dir = os.path.expanduser("~/Downloads")
        self.notebook_root = ""
        self.known_notebooks = []
        self.locale = "zh"
        self.config = dict(DEFAULT_CONFIG)
        self.notebook_configs = {}
        self.notebook_results = {}
        self.stats = {"total_synced": 0, "last_sync": ""}
        self.logs = []
        self.sync_meta = {}
        self.pending_confirm = None
        self._remote_preview_cache = {}
        self.kv_tooltip = False
        self.supports_checklist = False
        self.supports_form_layout = False
        self.supports_multi_notebook = False
        self.last_status = ""

    def _is_en(self):
        return self.locale.lower().startswith("en")

    def _tr(self, zh, en):
        return en if self._is_en() else zh

    def _emit_progress(self, bridge, done=None, total=None, progress=None, label=None):
        if not getattr(self, "supports_action_progress", False):
            return
        params = {}
        if done is not None:
            params["done"] = int(done)
        if total is not None:
            params["total"] = int(total)
        if progress is not None:
            params["progress"] = float(progress)
        if label:
            params["label"] = str(label)
        if not params:
            return
        try:
            if hasattr(bridge, "notify_progress"):
                bridge.notify_progress(**params)
            elif hasattr(bridge, "send"):
                bridge.send({"jsonrpc": "2.0", "method": "host.action.progress", "params": params})
        except Exception:
            pass

    def _localize_error(self, detail):
        if self._is_en() and CHINESE_TEXT.search(detail):
            return "The underlying error is unavailable in English"
        return detail

    def _error_detail(self, exc):
        return self._localize_error(sanitize_error_text(exc))

    def _norm_nb_path(self, raw):
        text = str(raw or "").strip()
        if not text:
            return ""
        return os.path.normpath(os.path.abspath(os.path.expanduser(text)))

    def _display_path(self, raw):
        path = self._norm_nb_path(raw)
        if not path:
            return ""
        home = os.path.normpath(os.path.expanduser("~"))
        if path == home:
            return "~"
        if path.startswith(home + os.sep):
            return "~" + path[len(home):]
        return path

    def _notebook_key(self, nb_root=None):
        raw = nb_root if nb_root is not None else self.notebook_root
        norm = self._norm_nb_path(raw)
        return norm or "default"

    def _notebook_label(self, nb_root=None):
        key = self._notebook_key(nb_root)
        if key == "default":
            return self._tr("默认笔记本", "Default notebook")
        return os.path.basename(key) or key

    def _notebook_slug(self, nb_root=None):
        key = self._notebook_key(nb_root)
        if key == "default":
            return "default"
        base = os.path.basename(key) or "notebook"
        safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in base).strip("-") or "notebook"
        return f"{safe[:24]}-{sha256_text(key)[:8]}"

    def _refresh_known_notebooks(self, bridge):
        entries = []
        seen = set()

        def add_entry(path_raw, name_raw="", active=False):
            norm = self._norm_nb_path(path_raw)
            if not norm or norm in seen:
                return
            seen.add(norm)
            label = str(name_raw or "").strip() or os.path.basename(norm) or norm
            entries.append({"path": norm, "name": label, "active": bool(active)})

        active_norm = self._norm_nb_path(self.notebook_root)
        if self.supports_multi_notebook and bridge is not None:
            try:
                res = bridge.call_host("host.notebooks.list", {})
                for item in res.get("notebooks") or []:
                    if isinstance(item, dict):
                        p = item.get("path")
                        add_entry(
                            p,
                            item.get("name"),
                            bool(item.get("active")) or (active_norm and self._norm_nb_path(p) == active_norm),
                        )
            except Exception:
                pass

        for existing in self.known_notebooks:
            if isinstance(existing, dict):
                p = existing.get("path")
                add_entry(p, existing.get("name"), active_norm and self._norm_nb_path(p) == active_norm)
            elif isinstance(existing, str):
                add_entry(existing, "", active_norm and self._norm_nb_path(existing) == active_norm)

        if active_norm:
            add_entry(active_norm, os.path.basename(active_norm) or active_norm, True)

        self.known_notebooks = entries
        return entries

    def _selected_notebooks(self, cfg=None):
        c = cfg if cfg is not None else self.config
        raw = c.get("selected_notebooks")
        known_paths = [e["path"] for e in self.known_notebooks]
        known_set = set(known_paths)
        out = []
        seen = set()
        if isinstance(raw, list):
            for item in raw:
                norm = self._norm_nb_path(item)
                if not norm or norm in seen:
                    continue
                if known_set and norm not in known_set:
                    continue
                seen.add(norm)
                out.append(norm)
        if not self.supports_multi_notebook:
            active_norm = self._norm_nb_path(self.notebook_root)
            return [active_norm] if active_norm else []
        return out

    def _legacy_root_owner(self, protocol, target_bases):
        candidates = []
        for nb, cfg in self.notebook_configs.items():
            if nb == "default" or cfg.get("protocol") != protocol:
                continue
            selected = cfg.get("selected_notebooks")
            if selected and selected != [nb]:
                continue
            if self._sync_target_base(cfg) in target_bases:
                candidates.append(nb)
        if len(candidates) == 1:
            return candidates[0]
        if not candidates and len(self.known_notebooks) == 1:
            return self.known_notebooks[0]["path"]
        raise RuntimeError(self._tr(
            "旧同步根目录缺少唯一的笔记本归属，无法安全继续同步",
            "The legacy sync root cannot be attributed to one notebook. Sync cannot safely continue.",
        ))

    def _valid_sync_subdir(self, subdir):
        return is_safe_rel_path(subdir) and "/" not in subdir and "\\" not in subdir

    def _notebook_subdir_map(self, notebooks, protocol, target_bases):
        layout_key = f"{protocol}:{target_bases[0]}"
        layouts = self.sync_meta.get(LAYOUTS_META_KEY, {})
        stored = layouts.get(layout_key, {}) if isinstance(layouts, dict) else {}
        bindings = dict(stored) if isinstance(stored, dict) else {}
        for subdir in bindings.values():
            if not isinstance(subdir, str) or (subdir and not self._valid_sync_subdir(subdir)):
                raise RuntimeError(self._tr("保存的笔记本同步目录无效", "The saved notebook sync folder is invalid"))
        historical = {}
        legacy_root = False
        marker = f"|{protocol}:"
        legacy_keys = {f"{protocol}:{base}" for base in target_bases}
        for key, entry in self.sync_meta.items():
            if not isinstance(entry, dict):
                continue
            if key in legacy_keys:
                legacy_root = True
                continue
            if not key.startswith("nb:") or marker not in key:
                continue
            nb, location = key[3:].rsplit(marker, 1)
            for base in target_bases:
                if location == base:
                    historical.setdefault(nb, set()).add("")
                    break
                if location.startswith(base + "::"):
                    subdir = location[len(base) + 2:]
                    if self._valid_sync_subdir(subdir):
                        historical.setdefault(nb, set()).add(subdir)
                    break

        if legacy_root and not any("" in dirs for dirs in historical.values()) and "" not in bindings.values():
            owner = self._legacy_root_owner(protocol, target_bases)
            historical.setdefault(owner, set()).add("")

        # Reserve old directories even after their owners are deselected.
        owners = {}
        for nb in set(bindings) | set(historical):
            dirs = set(historical.get(nb, ()))
            if nb in bindings:
                dirs.add(bindings[nb])
            for subdir in dirs:
                folded = sync_dir_key(subdir)
                if folded in owners and owners[folded] != nb:
                    raise RuntimeError(self._tr(
                        "同步目标的旧路径被多个笔记本共用，无法安全继续同步",
                        "Multiple notebooks share the legacy sync path. Sync cannot safely continue.",
                    ))
                owners[folded] = nb
            if nb not in bindings:
                if "" in dirs:
                    bindings[nb] = ""
                elif len(dirs) == 1:
                    bindings[nb] = next(iter(dirs))
                elif nb in notebooks:
                    raise RuntimeError(self._tr(
                        f"笔记本「{self._notebook_label(nb)}」有多个旧同步目录，无法安全选择",
                        f"Notebook {self._notebook_label(nb)} has multiple legacy sync folders. A folder cannot be chosen safely.",
                    ))

        if not owners and len(notebooks) == 1:
            bindings[notebooks[0]] = ""
            return layout_key, bindings, set()

        names = {}
        name_counts = {}
        for nb in notebooks:
            if nb in bindings:
                continue
            name = os.path.basename(nb).strip().strip(".") or "notebook"
            name = name.replace("\\", "-")
            names[nb] = name
            folded = sync_dir_key(name)
            name_counts[folded] = name_counts.get(folded, 0) + 1

        for nb, name in sorted(names.items()):
            folded = sync_dir_key(name)
            # Beside a legacy root, an ordinary folder name can belong to that notebook.
            if "" in owners or folded in owners or folded == "assets" or name_counts[folded] > 1:
                name = f"{name}-{sha256_text(nb)[:8]}"
                folded = sync_dir_key(name)
            suffix = 2
            subdir = name
            while folded in owners:
                subdir = f"{name}-{suffix}"
                folded = sync_dir_key(subdir)
                suffix += 1
            bindings[nb] = subdir
            owners[folded] = nb

        return layout_key, bindings, set(owners) - {""}

    def _meta_key(self, protocol, target_id, nb_key=None):
        nb = nb_key or self._notebook_key()
        return f"nb:{nb}|{protocol}:{target_id}"

    def _get_base_map(self, *keys):
        for key in keys:
            if isinstance(self.sync_meta.get(key), dict):
                return dict(self.sync_meta[key])
        return {}

    def _load_state(self, bridge):
        self._refresh_known_notebooks(bridge)
        nb_key = self._notebook_key()
        nb_cfgs_res = bridge.call_host("host.storage.get", {"key": "notebook_configs"})
        if nb_cfgs_res.get("found") and isinstance(nb_cfgs_res.get("value"), dict):
            self.notebook_configs = {
                str(k): self._normalize_config(v, base=DEFAULT_CONFIG)
                for k, v in nb_cfgs_res["value"].items()
                if isinstance(v, dict)
            }

        cfg_res = bridge.call_host("host.storage.get", {"key": "config"})
        raw_cfg = cfg_res.get("value") if (cfg_res.get("found") and isinstance(cfg_res.get("value"), dict)) else None
        if raw_cfg is not None and "selected_notebooks" in raw_cfg:
            self.config = self._normalize_config(raw_cfg, base=DEFAULT_CONFIG)
        elif nb_key in self.notebook_configs:
            self.config = self._normalize_config(self.notebook_configs[nb_key], base=DEFAULT_CONFIG)
            if self.notebook_root:
                self.config["selected_notebooks"] = [self._norm_nb_path(self.notebook_root)]
        elif raw_cfg is not None:
            self.config = self._normalize_config(raw_cfg, base=DEFAULT_CONFIG)
            if self.notebook_root and not self.config["selected_notebooks"]:
                self.config["selected_notebooks"] = [self._norm_nb_path(self.notebook_root)]
        else:
            self.config = dict(DEFAULT_CONFIG)
            if self.notebook_root:
                self.config["selected_notebooks"] = [self._norm_nb_path(self.notebook_root)]

        nb_res = bridge.call_host("host.storage.get", {"key": "notebook_results"})
        if nb_res.get("found") and isinstance(nb_res.get("value"), dict):
            self.notebook_results = {
                str(k): v for k, v in nb_res["value"].items() if isinstance(v, dict)
            }

        stats_res = bridge.call_host("host.storage.get", {"key": "stats"})
        if stats_res.get("found") and isinstance(stats_res.get("value"), dict):
            val = stats_res["value"]
            self.stats = {
                "total_synced": int(val.get("total_synced", 0) or 0),
                "last_sync": str(val.get("last_sync", "") or ""),
            }

        logs_res = bridge.call_host("host.storage.get", {"key": "logs"})
        if logs_res.get("found") and isinstance(logs_res.get("value"), list):
            self.logs = [
                self._normalize_log(entry)
                for entry in logs_res["value"]
                if isinstance(entry, dict)
            ][:MAX_LOG_ENTRIES]

        meta_res = bridge.call_host("host.storage.get", {"key": "sync_meta"})
        if meta_res.get("found") and isinstance(meta_res.get("value"), dict):
            self.sync_meta = meta_res["value"]

        pc_res = bridge.call_host("host.storage.get", {"key": "pending_confirm"})
        self.pending_confirm = (
            self._normalize_pending_confirm(pc_res.get("value"))
            if pc_res.get("found")
            else None
        )
        self._remote_preview_cache = {}
        self.last_status = ""

    def _normalize_pending_confirm(self, raw):
        if not isinstance(raw, dict):
            return None
        scope_key = str(raw.get("scope_key") or "").strip()
        fingerprint = str(raw.get("fingerprint") or "").strip()
        protocol = str(raw.get("protocol") or "").strip()
        reasons = [str(r).strip() for r in (raw.get("reasons") or []) if str(r or "").strip()]
        if not scope_key or not fingerprint or protocol not in VALID_PROTOCOLS or not reasons:
            return None
        sample_lines = [str(s).strip() for s in (raw.get("sample_lines") or []) if str(s or "").strip()]
        return {
            "scope_key": scope_key,
            "fingerprint": fingerprint,
            "protocol": protocol,
            "target_display": str(raw.get("target_display") or "").strip(),
            "reasons": reasons,
            "badge": str(raw.get("badge") or "").strip(),
            "sample_lines": sample_lines,
        }

    def _clear_pending_confirm(self, bridge=None):
        had = self.pending_confirm is not None
        self.pending_confirm = None
        if had and bridge is not None:
            bridge.call_host("host.storage.set", {"key": "pending_confirm", "value": None})

    def _normalize_log(self, entry):
        title = str(entry.get("title") or "同步事件").strip() or "同步事件"
        time_str = str(entry.get("time") or "").strip()
        raw_status = str(entry.get("status") or "").strip()
        raw_tone = str(entry.get("tone") or "").strip().lower()
        raw_tooltip = str(entry.get("tooltip") or "").strip()

        status, inferred_tone, extra_tip = self._classify_log_status(raw_status)
        tone = raw_tone if raw_tone in ("success", "warning", "danger", "info") else inferred_tone
        tooltip = raw_tooltip or extra_tip

        item = {"title": title, "status": status, "time": time_str, "tone": tone}
        if tooltip and tooltip != title and tooltip != status:
            item["tooltip"] = tooltip
        if entry.get("locale") == "en":
            item["locale"] = "en"
        return item

    def _log_for_page(self, entry):
        item = self._normalize_log(entry)
        recorded_in_english = item.pop("locale", None) == "en"
        if not self._is_en():
            return item

        status = item["status"]
        status = LOG_STATUS_EN.get(status, status)
        item["status"] = "Complete" if CHINESE_TEXT.search(status) else status
        # Older entries store free-form Chinese messages without translation keys.
        if not recorded_in_english:
            if CHINESE_TEXT.search(item["title"]):
                item["title"] = "Sync event"
            if CHINESE_TEXT.search(item.get("tooltip", "")):
                item.pop("tooltip")
        return item

    def _classify_log_status(self, raw_status):
        s = str(raw_status or "").strip()
        if not s:
            return "完成", "info", ""
        exact = {
            "成功": ("成功", "success"),
            "通过": ("通过", "success"),
            "完成": ("成功", "success"),
            "无变更": ("无变更", "info"),
            "待确认": ("待确认", "warning"),
            "失败": ("失败", "danger"),
            "未连通": ("未连通", "danger"),
            "已取消": ("已取消", "info"),
            "冲突副本": ("冲突副本", "warning"),
        }
        if s in exact:
            st, tn = exact[s]
            return st, tn, ""
        if s == "用户已取消" or "已取消" in s:
            return "已取消", "info", s
        if "未连通" in s:
            return "未连通", "danger", s
        if any(tok in s for tok in ("失败", "未完成", "异常", "错误", "请先填写")):
            return "失败", "danger", s
        if any(tok in s for tok in ("删除保护", "暂停", "待确认", "危险变更")):
            return "待确认", "warning", s
        if "冲突" in s:
            return "冲突副本", "warning", s
        if any(tok in s for tok in ("已是最新", "无变更")):
            return "无变更", "info", s
        if any(tok in s for tok in ("已镜像", "已从", "优先", "已推送", "已上传", "已下载", "已拉取", "同步 ", "模式:")):
            return "成功", "success", s
        return s, "info", ""

    def _normalize_config(self, raw, base=None):
        merged = dict(DEFAULT_CONFIG)
        merged["selected_notebooks"] = list(DEFAULT_CONFIG["selected_notebooks"])
        src_base = base if base is not None else self.config
        merged.update(src_base)
        if isinstance(src_base.get("selected_notebooks"), list):
            merged["selected_notebooks"] = [
                self._norm_nb_path(p) for p in src_base["selected_notebooks"] if self._norm_nb_path(p)
            ]
        if not isinstance(raw, dict):
            return merged

        if "selected_notebooks" in raw and isinstance(raw["selected_notebooks"], list):
            dedup = []
            seen = set()
            for item in raw["selected_notebooks"]:
                norm = self._norm_nb_path(item)
                if norm and norm not in seen:
                    seen.add(norm)
                    dedup.append(norm)
            merged["selected_notebooks"] = dedup

        protocol = raw.get("protocol", merged["protocol"])
        if protocol in VALID_PROTOCOLS:
            merged["protocol"] = protocol

        str_fields = (
            "mirror_dir",
            "sync_scope",
            "webdav_url",
            "webdav_dir",
            "webdav_user",
            "webdav_pass",
            "git_remote",
            "git_branch",
            "git_token",
        )
        for key in str_fields:
            if key in raw and raw[key] is not None:
                val = str(raw[key])
                merged[key] = val if key in ("mirror_dir", "webdav_pass", "git_token") else val.strip()

        # Resolve old presets once. Current controls store the actual paths and branch.
        mirror_preset = raw.get("mirror_preset")
        if mirror_preset == "downloads":
            merged["mirror_dir"] = os.path.join(self._downloads_root(), "Block-Sync")
        elif mirror_preset == "documents":
            merged["mirror_dir"] = os.path.expanduser("~/Documents/Block-Sync")
        elif mirror_preset == "custom" and not merged["mirror_dir"]:
            merged["mirror_dir"] = os.path.join(self._downloads_root(), "Block-Sync")

        webdav_dir_preset = raw.get("webdav_dir_preset")
        if webdav_dir_preset in ("/BlockNotes", "/Notes", "/Markdown"):
            merged["webdav_dir"] = webdav_dir_preset
        git_branch_preset = raw.get("git_branch_preset")
        if git_branch_preset in ("main", "master"):
            merged["git_branch"] = git_branch_preset

        if not merged["sync_scope"]:
            merged["sync_scope"] = "all"

        # Backward compatibility with legacy target_path / secret_token keys
        legacy_target = str(raw.get("target_path") or raw.get("endpoint_url") or "").strip()
        if legacy_target:
            if merged["protocol"] == "local_mirror" and not merged["mirror_dir"]:
                merged["mirror_dir"] = legacy_target
            elif merged["protocol"] == "webdav" and not merged["webdav_url"]:
                merged["webdav_url"] = legacy_target
            elif merged["protocol"] == "git" and not merged["git_remote"]:
                merged["git_remote"] = legacy_target

        legacy_secret = str(raw.get("secret_token") or "")
        if legacy_secret:
            if merged["protocol"] == "webdav" and not merged["webdav_pass"]:
                if ":" in legacy_secret and not merged["webdav_user"]:
                    user_part, pass_part = legacy_secret.split(":", 1)
                    merged["webdav_user"] = user_part.strip()
                    merged["webdav_pass"] = pass_part
                else:
                    merged["webdav_pass"] = legacy_secret
            elif merged["protocol"] == "git" and not merged["git_token"]:
                merged["git_token"] = legacy_secret

        if not merged["webdav_dir"]:
            merged["webdav_dir"] = "/BlockNotes"
        if not merged["git_branch"]:
            merged["git_branch"] = "main"

        git_auth = raw.get("git_auth", merged["git_auth"])
        if git_auth in VALID_GIT_AUTHS:
            merged["git_auth"] = git_auth

        for bool_key in ("auto_sync", "sync_assets", "delete_guard"):
            if bool_key in raw:
                merged[bool_key] = bool(raw[bool_key])

        policy = raw.get("conflict_policy", merged["conflict_policy"])
        if policy in VALID_CONFLICT_POLICIES:
            merged["conflict_policy"] = policy

        merged["mirror_dir"] = self._resolve_mirror_dir(merged)
        return merged

    def _save_config(self, bridge):
        self.notebook_configs[self._notebook_key()] = dict(self.config)
        bridge.call_host("host.storage.set", {"key": "notebook_configs", "value": self.notebook_configs})
        bridge.call_host("host.storage.set", {"key": "config", "value": self.config})

    def _save_runtime(self, bridge):
        bridge.call_host("host.storage.set", {"key": "stats", "value": self.stats})
        bridge.call_host("host.storage.set", {"key": "logs", "value": self.logs[:MAX_LOG_ENTRIES]})
        bridge.call_host("host.storage.set", {"key": "sync_meta", "value": self.sync_meta})
        bridge.call_host("host.storage.set", {"key": "notebook_results", "value": self.notebook_results})
        bridge.call_host("host.storage.set", {"key": "pending_confirm", "value": self.pending_confirm})

    def _result_key(self):
        return "__multi__" if self.supports_multi_notebook else self._notebook_key()

    def _record_result(self, status, summary, protocol=None, target="", pushed=0, pulled=0, conflicts=0, assets=0):
        nb_key = self._result_key()
        proto = protocol or self.config.get("protocol", "local_mirror")
        proto_label = self._protocol_label(proto)
        target_str = str(target or self._target_display(self.config))
        now_str = now_hms()
        status_str = str(status or "完成")
        summary_str = str(summary or "完成")

        prev = self.notebook_results.get(nb_key)
        prev_success = (
            dict(prev.get("last_success"))
            if isinstance(prev, dict) and isinstance(prev.get("last_success"), dict)
            else None
        )
        if status_str in ("成功", "无变更"):
            last_success = {
                "status": status_str,
                "protocol": proto_label,
                "target": target_str,
                "time": now_str,
                "pushed": int(pushed or 0),
                "pulled": int(pulled or 0),
                "conflicts": int(conflicts or 0),
                "assets": int(assets or 0),
                "summary": summary_str,
            }
        else:
            last_success = prev_success

        entry = {
            "status": status_str,
            "protocol": proto_label,
            "target": target_str,
            "time": now_str,
            "pushed": int(pushed or 0),
            "pulled": int(pulled or 0),
            "conflicts": int(conflicts or 0),
            "assets": int(assets or 0),
            "summary": summary_str,
        }
        if self._is_en():
            entry["locale"] = "en"
        if last_success is not None:
            entry["last_success"] = last_success
        self.notebook_results[nb_key] = entry

    def _get_last_result(self):
        return self.notebook_results.get(self._result_key()) or self.notebook_results.get(self._notebook_key())

    def _target_display(self, cfg=None):
        c = cfg or self.config
        protocol = c.get("protocol", "local_mirror")
        if protocol == "local_mirror":
            return self._resolve_mirror_dir(c)
        if protocol == "webdav":
            return self._webdav_base_url(c) or self._tr("未配置 WebDAV 地址", "WebDAV address is missing")
        target = str(c.get("git_remote") or "").strip()
        branch = self._git_branch(c)
        repo_dir = self._resolve_local_git_dir(c)
        return f"{target} ({branch})" if target else f"{repo_dir} ({branch})"

    def _append_log(self, title, status, tone="", tooltip=""):
        entry = self._normalize_log({
            "title": str(title or self._tr("同步任务", "Sync task")).strip() or self._tr("同步任务", "Sync task"),
            "status": str(status or "成功").strip() or "成功",
            "time": now_hms(),
            "tone": tone,
            "tooltip": tooltip,
        })
        if self._is_en():
            entry["locale"] = "en"
        self.logs.insert(0, entry)
        self.logs = self.logs[:MAX_LOG_ENTRIES]

    def _protocol_label(self, protocol):
        return {
            "local_mirror": self._tr("目录镜像", "Local mirror"),
            "webdav": "WebDAV",
            "git": self._tr("Git 仓库", "Git repository"),
        }.get(protocol, self._tr("目录镜像", "Local mirror"))

    def _downloads_root(self):
        raw = (self.downloads_dir or "").strip() or "~/Downloads"
        return os.path.normpath(os.path.expanduser(raw))

    def _resolve_mirror_dir(self, cfg=None):
        c = cfg or self.config
        raw = str(c.get("mirror_dir") or "")
        if not raw:
            return ""
        expanded = os.path.expanduser(raw)
        if os.path.isabs(expanded):
            return os.path.normpath(expanded)
        return os.path.normpath(os.path.join(self._downloads_root(), expanded))

    def _resolve_webdav_dir(self, cfg=None):
        c = cfg or self.config
        return str(c.get("webdav_dir") or "").strip() or "/BlockNotes"

    def _target_error(self, cfg, require_notebooks=True):
        selected = self._selected_notebooks(cfg)
        if require_notebooks and self.supports_multi_notebook and not selected:
            return self._tr("请至少选择一个笔记本", "Select at least one notebook")
        protocol = cfg["protocol"]
        if protocol == "webdav":
            if not self._webdav_base_url(cfg):
                return self._tr("请填写有效的 WebDAV 地址", "Enter a valid WebDAV address")
        elif protocol == "git":
            if not str(cfg.get("git_remote") or "").strip():
                return self._tr("请填写 Git 仓库地址", "Enter a Git repository address")
        elif protocol == "local_mirror":
            target = self._resolve_mirror_dir(cfg)
            if not target:
                return self._tr("请先选择同步文件夹", "Select a sync folder first")
            target_real = os.path.realpath(target)
            roots_to_check = selected if selected else ([self.notebook_root] if self.notebook_root else [])
            for nb in roots_to_check:
                if not nb:
                    continue
                source = os.path.realpath(nb)
                try:
                    overlaps = os.path.commonpath((source, target_real)) in (source, target_real)
                except ValueError:
                    overlaps = False
                if overlaps:
                    return self._tr(
                        f"同步文件夹不能与笔记本「{self._notebook_label(nb)}」重叠",
                        f"The sync folder cannot overlap with notebook {self._notebook_label(nb)}",
                    )
        return ""

    def _matches_scope(self, rel_path, scope=None):
        sc = scope if scope is not None else self.config.get("sync_scope", "all")
        if not sc or sc == "all":
            return True
        return rel_path.startswith(f"{sc}/")

    def _list_local_note_paths(self, bridge, nb_root=None):
        params = {}
        if nb_root and self.supports_multi_notebook:
            params["notebook_root"] = nb_root
        listed = bridge.call_host("host.notes.list", params).get("notes") or []
        paths = []
        for item in listed:
            rel_path = str(item.get("path") or "").replace("\\", "/")
            if is_safe_rel_md(rel_path) and not is_safe_rel_asset(rel_path):
                paths.append(rel_path)
        return sorted(set(paths))

    def _read_local_notes(self, bridge, only_path=None, scope=None, paths=None, nb_root=None):
        notes = {}
        all_paths = paths if paths is not None else self._list_local_note_paths(bridge, nb_root=nb_root)
        for rel_path in all_paths:
            if not is_safe_rel_md(rel_path):
                continue
            if only_path and rel_path != only_path:
                continue
            if not only_path and not self._matches_scope(rel_path, scope):
                continue
            params = {"path": rel_path}
            if nb_root and self.supports_multi_notebook:
                params["notebook_root"] = nb_root
            res = bridge.call_host("host.notes.read", params)
            notes[rel_path] = str(res.get("content") or "")
        return notes

    def _write_local_note(self, bridge, rel_path, content, nb_root=None, expected_revision=""):
        params = {"path": rel_path, "content": content, "expected_revision": expected_revision}
        if nb_root and self.supports_multi_notebook:
            params["notebook_root"] = nb_root
        bridge.call_host("host.notes.write", params)

    def _asset_file(self, root_dir, rel_path):
        if not is_safe_rel_asset(rel_path):
            raise ValueError(self._tr(f"无效的附件路径：{rel_path}", f"Invalid attachment path: {rel_path}"))
        root_real = os.path.realpath(root_dir)
        path = os.path.join(root_real, *rel_path.split("/"))
        if not os.path.realpath(path).startswith(root_real + os.sep):
            raise ValueError(self._tr(f"附件路径超出同步目录：{rel_path}", f"Attachment path is outside the sync folder: {rel_path}"))
        return path

    def _read_asset_file(self, root_dir, rel_path):
        try:
            with open(self._asset_file(root_dir, rel_path), "rb") as fh:
                return fh.read()
        except FileNotFoundError:
            return None

    def _asset_mtime(self, root_dir, rel_path):
        try:
            return os.stat(self._asset_file(root_dir, rel_path)).st_mtime_ns
        except OSError:
            return None

    def _list_dir_assets(self, root_dir, excluded_subdirs=()):
        names = set()
        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            if root == root_dir:
                dirs[:] = [d for d in dirs if sync_dir_key(d) not in excluded_subdirs]
            for name in files:
                rel = os.path.relpath(os.path.join(root, name), root_dir).replace(os.sep, "/")
                if is_safe_rel_asset(rel):
                    names.add(rel)
        return names

    def _sync_assets(
        self,
        paths,
        read_local,
        read_remote,
        write_local,
        write_remote,
        policy,
        base_map=None,
        local_mtime=None,
        remote_mtime=None,
    ):
        synced = 0
        for rel in sorted(paths):
            local_data = read_local(rel)
            remote_data = read_remote(rel)
            base_key = f"asset:{rel}"
            if local_data is None and remote_data is None:
                continue
            if local_data == remote_data:
                if base_map is not None:
                    base_map[base_key] = sha256_bytes(local_data)
                continue
            if local_data is None:
                write_local(rel, remote_data)
                if base_map is not None:
                    base_map[base_key] = sha256_bytes(remote_data)
            elif remote_data is None:
                write_remote(rel, local_data)
                if base_map is not None:
                    base_map[base_key] = sha256_bytes(local_data)
            else:
                local_hash = sha256_bytes(local_data)
                remote_hash = sha256_bytes(remote_data)
                base_hash = base_map.get(base_key) if base_map is not None else None
                remote_strictly_newer = False
                if base_hash is None and local_mtime is not None and remote_mtime is not None:
                    lm = local_mtime(rel)
                    rm = remote_mtime(rel)
                    remote_strictly_newer = lm is not None and rm is not None and rm > lm
                if (
                    (base_hash is not None and local_hash == base_hash and remote_hash != base_hash)
                    or (base_hash is None and policy == "local_first" and remote_strictly_newer)
                ):
                    write_local(rel, remote_data)
                    if base_map is not None:
                        base_map[base_key] = remote_hash
                elif base_hash is not None and remote_hash == base_hash and local_hash != base_hash:
                    write_remote(rel, local_data)
                    if base_map is not None:
                        base_map[base_key] = local_hash
                elif policy == "remote_first":
                    write_local(rel, remote_data)
                    if base_map is not None:
                        base_map[base_key] = remote_hash
                else:
                    if policy == "keep_both":
                        stem, ext = posixpath.splitext(rel)
                        fingerprint = remote_hash[:16]
                        suffix = ""
                        attempt = 1
                        while True:
                            copy_rel = f"{stem}.conflict-{fingerprint}{suffix}{ext}"
                            local_copy = read_local(copy_rel)
                            remote_copy = read_remote(copy_rel)
                            if local_copy in (None, remote_data) and remote_copy in (None, remote_data):
                                break
                            attempt += 1
                            suffix = f"-{attempt}"

                        # Keep a copy on each side before replacing the original. The
                        # content-based name also works when just one copy was saved.
                        if local_copy is None:
                            write_local(copy_rel, remote_data)
                        if remote_copy is None:
                            write_remote(copy_rel, remote_data)
                        if base_map is not None:
                            base_map[f"asset:{copy_rel}"] = remote_hash
                    write_remote(rel, local_data)
                    if base_map is not None:
                        base_map[base_key] = local_hash
            synced += 1
        return synced

    def _asset_paths_for_sync(self, root_dir, paths, excluded_subdirs):
        local_paths = self._list_dir_assets(root_dir) if paths is None else paths
        for rel in local_paths:
            if in_sync_subdir(rel, excluded_subdirs):
                raise RuntimeError(self._tr(f"附件路径与其他笔记本的同步目录重叠：{rel}", f"Attachment path overlaps with another notebook's sync folder: {rel}"))
        return local_paths

    def _check_delete_guard(self, base_map, local_notes, remote_notes, only_path=None):
        if only_path is not None or not self.config.get("delete_guard", True):
            return None
        remote_missing = [
            p for p in base_map
            if is_safe_rel_md(p) and p in local_notes and p not in remote_notes
        ]
        if len(remote_missing) > DELETE_GUARD_THRESHOLD:
            return (
                self._tr(
                    f"已触发删除保护：远端缺失 {len(remote_missing)} 篇已同步笔记",
                    f"Deletion protection paused sync: {len(remote_missing)} synced notes are missing remotely",
                )
                + self._tr(f"（超过 {DELETE_GUARD_THRESHOLD} 篇），已暂停同步", f" (limit: {DELETE_GUARD_THRESHOLD})")
            )
        local_missing = [
            p for p in base_map
            if is_safe_rel_md(p) and p in remote_notes and p not in local_notes
        ]
        if len(local_missing) > DELETE_GUARD_THRESHOLD:
            return (
                self._tr(
                    f"已触发删除保护：本地缺失 {len(local_missing)} 篇已同步笔记",
                    f"Deletion protection paused sync: {len(local_missing)} synced notes are missing locally",
                )
                + self._tr(f"（超过 {DELETE_GUARD_THRESHOLD} 篇），已暂停同步", f" (limit: {DELETE_GUARD_THRESHOLD})")
            )
        return None

    def _resolve_conflict_pair(self, rel_path, local_text, remote_text, base_hash, policy=None):
        local_hash = sha256_text(local_text)
        remote_hash = sha256_text(remote_text)
        if local_hash == remote_hash:
            return "skip", local_text, None, local_hash

        if base_hash and base_hash == local_hash:
            return "pull", remote_text, None, remote_hash
        if base_hash and base_hash == remote_hash:
            return "push", local_text, None, local_hash

        eff_policy = policy if policy is not None else self.config.get("conflict_policy", "keep_both")
        if eff_policy == "local_first":
            return "push", local_text, None, local_hash
        if eff_policy == "remote_first":
            return "pull", remote_text, None, remote_hash

        conflict_rel = make_conflict_path(rel_path, conflict_stamp())
        return "keep_both", local_text, (conflict_rel, remote_text), local_hash

    def _sync_local_dir_assets(self, remote_dir, nb_root=None, paths=None, excluded_subdirs=(), cfg=None, base_map=None):
        c = cfg or self.config
        root_dir = nb_root or self.notebook_root
        if not c.get("sync_assets", True) or not root_dir:
            return 0
        local_paths = self._asset_paths_for_sync(root_dir, paths, excluded_subdirs)
        candidates = local_paths if paths is not None else local_paths | self._list_dir_assets(remote_dir, excluded_subdirs)
        return self._sync_assets(
            candidates,
            lambda rel: self._read_asset_file(root_dir, rel),
            lambda rel: self._read_asset_file(remote_dir, rel),
            lambda rel, data: self._write_mirror_bytes(root_dir, rel, data),
            lambda rel, data: self._write_mirror_bytes(remote_dir, rel, data),
            c.get("conflict_policy", "keep_both"),
            base_map=base_map,
            local_mtime=lambda rel: self._asset_mtime(root_dir, rel),
            remote_mtime=lambda rel: self._asset_mtime(remote_dir, rel),
        )

    # ---------- Local Mirror Mode ----------

    def _test_local_mirror(self):
        mirror_dir = self._resolve_mirror_dir()
        try:
            os.makedirs(mirror_dir, exist_ok=True)
            probe_file = os.path.join(mirror_dir, ".block-sync-probe")
            with open(probe_file, "w", encoding="utf-8") as fh:
                fh.write("ok")
            os.remove(probe_file)
            return True, self._tr(f"目录镜像可用: {mirror_dir}", f"Local mirror is available: {mirror_dir}")
        except Exception as exc:
            return False, self._tr(f"目录镜像不可写: {self._error_detail(exc)}", f"Local mirror is not writable: {self._error_detail(exc)}")

    def _scan_mirror_files(self, mirror_dir, only_path=None, scope=None, excluded_subdirs=()):
        remote_files = {}
        if not os.path.isdir(mirror_dir):
            return remote_files
        if only_path:
            if is_safe_rel_asset(only_path) or in_sync_subdir(only_path, excluded_subdirs):
                return remote_files
            candidate = os.path.join(mirror_dir, *only_path.split("/"))
            if os.path.isfile(candidate):
                with open(candidate, "r", encoding="utf-8", errors="replace") as fh:
                    remote_files[only_path] = fh.read()
            return remote_files

        for root, dirs, files in os.walk(mirror_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "assets"]
            if root == mirror_dir:
                dirs[:] = [d for d in dirs if sync_dir_key(d) not in excluded_subdirs]
            for name in files:
                if name.startswith("."):
                    continue
                full = os.path.join(root, name)
                rel = os.path.relpath(full, mirror_dir).replace(os.sep, "/")
                if not is_safe_rel_md(rel) or in_sync_subdir(rel, excluded_subdirs) or not self._matches_scope(rel, scope):
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    remote_files[rel] = fh.read()
        return remote_files

    def _write_mirror_file(self, mirror_dir, rel_path, content, expected_hash=None, create_only=False):
        dest = os.path.join(mirror_dir, *rel_path.split("/"))
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        content_hash = sha256_text(content)
        change_err = self._tr(
            f"目标文件已变更，已中止覆盖以避免数据丢失：{rel_path}",
            f"Destination file changed during sync; aborted overwrite to protect data: {rel_path}",
        )
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=parent or mirror_dir,
                prefix=".block-sync-",
                suffix=".tmp",
                delete=False,
            ) as fh:
                temp_path = fh.name
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            # Verify destination right before committing so edits or deletions after planning are never clobbered.
            if create_only:
                try:
                    os.link(temp_path, dest)
                    return
                except FileExistsError:
                    with open(dest, "r", encoding="utf-8", errors="replace") as existing_fh:
                        if sha256_text(existing_fh.read()) == content_hash:
                            return
                    raise RuntimeError(change_err)
                except OSError as err:
                    # Only fall back to O_CREAT|O_EXCL when the filesystem lacks hardlink support.
                    if err.errno not in (
                        errno.EXDEV,
                        errno.ENOTSUP,
                        errno.EOPNOTSUPP,
                        errno.ENOSYS,
                        errno.EMLINK,
                    ):
                        raise
                    try:
                        excl_fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                    except FileExistsError:
                        with open(dest, "r", encoding="utf-8", errors="replace") as existing_fh:
                            if sha256_text(existing_fh.read()) == content_hash:
                                return
                        raise RuntimeError(change_err)
                    try:
                        with os.fdopen(excl_fd, "w", encoding="utf-8") as out_fh:
                            out_fh.write(content)
                            out_fh.flush()
                            os.fsync(out_fh.fileno())
                    except BaseException:
                        try:
                            os.unlink(dest)
                        except OSError:
                            pass
                        raise
                    return
            elif expected_hash is not None:
                try:
                    existing_fd = os.open(dest, os.O_RDONLY)
                except FileNotFoundError:
                    raise RuntimeError(change_err)
                try:
                    if fcntl is not None:
                        try:
                            fcntl.flock(existing_fd, fcntl.LOCK_EX)
                        except OSError as err:
                            if err.errno not in (
                                errno.ENOTSUP,
                                errno.EOPNOTSUPP,
                                errno.ENOSYS,
                                errno.ENOLCK,
                                errno.EINVAL,
                            ):
                                raise
                    st_before = os.fstat(existing_fd)
                    chunks = []
                    while True:
                        buf = os.read(existing_fd, 65536)
                        if not buf:
                            break
                        chunks.append(buf)
                    cur_hash = sha256_text(b"".join(chunks).decode("utf-8", errors="replace"))
                    if cur_hash != expected_hash and cur_hash != content_hash:
                        raise RuntimeError(change_err)
                    try:
                        st_now = os.lstat(dest)
                    except FileNotFoundError:
                        raise RuntimeError(change_err)
                    if (
                        st_now.st_dev != st_before.st_dev
                        or st_now.st_ino != st_before.st_ino
                        or st_now.st_size != st_before.st_size
                        or st_now.st_mtime_ns != st_before.st_mtime_ns
                    ):
                        raise RuntimeError(change_err)
                    if os.name == "nt":
                        os.close(existing_fd)
                        existing_fd = -1
                    os.replace(temp_path, dest)
                    temp_path = None
                finally:
                    if existing_fd >= 0:
                        os.close(existing_fd)
                return
            os.replace(temp_path, dest)
            temp_path = None
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def _cleanup_stale_temp_files(self, root_dir, cfg=None):
        if not root_dir or not os.path.isdir(root_dir):
            return
        tracked_paths = set()
        if os.path.isdir(os.path.join(root_dir, ".git")):
            # Read git ls-files -z in binary mode so filenames containing '\r' are preserved verbatim.
            ls_proc = subprocess.run(
                ["git", "ls-files", "-z"],
                cwd=root_dir,
                env=self._git_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                timeout=8,
            )
            if ls_proc.returncode != 0:
                stderr_txt = (ls_proc.stderr or ls_proc.stdout or b"").decode("utf-8", errors="replace")
                err = self._error_detail(stderr_txt or self._tr("git ls-files 失败", "git ls-files failed"))
                raise RuntimeError(self._tr(f"Git 文件列表检查失败: {err}", f"Git file list check failed: {err}"))
            for raw_entry in (ls_proc.stdout or b"").split(b"\0"):
                if raw_entry:
                    tracked_paths.add(os.fsdecode(raw_entry).replace(os.sep, "/"))

        def on_walk_error(err):
            detail = f"{err.filename or root_dir} ({err})"
            raise RuntimeError(self._tr(
                f"无法扫描目录，已中止提交：{detail}",
                f"Could not scan directory; aborted commit: {detail}",
            ))

        for cur_root, dirs, file_names in os.walk(root_dir, onerror=on_walk_error):
            dirs[:] = [d for d in dirs if d != ".git"]
            for name in file_names:
                if name.startswith(".block-sync-") and name.endswith(".tmp"):
                    full = os.path.join(cur_root, name)
                    rel = os.path.relpath(full, root_dir).replace(os.sep, "/")
                    if rel in tracked_paths:
                        continue
                    try:
                        os.unlink(full)
                    except FileNotFoundError:
                        # Already removed concurrently; nothing left to stage.
                        pass
                    except OSError as err:
                        detail = f"{rel} ({err})"
                        raise RuntimeError(self._tr(
                            f"无法清理残留临时文件，已中止提交：{detail}",
                            f"Could not clean up stale temporary files; aborted commit: {detail}",
                        ))

    def _write_mirror_bytes(self, mirror_dir, rel_path, data):
        dest = self._asset_file(mirror_dir, rel_path)
        parent = os.path.dirname(dest)
        os.makedirs(parent, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=parent,
                prefix=".block-sync-",
                suffix=".tmp",
                delete=False,
            ) as fh:
                temp_path = fh.name
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp_path, dest)
            temp_path = None
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def _sync_local_mirror(self, bridge, only_path=None):
        mirror_dir = self._resolve_mirror_dir()
        os.makedirs(mirror_dir, exist_ok=True)

        local_notes = self._read_local_notes(bridge, only_path=only_path)
        remote_notes = self._scan_mirror_files(mirror_dir, only_path=only_path)

        meta_key = f"local_mirror:{mirror_dir}"
        base_map = dict(self.sync_meta.get(meta_key) or {})

        guard_msg = self._check_delete_guard(base_map, local_notes, remote_notes, only_path=only_path)
        if guard_msg:
            self._append_log(self._tr("删除保护暂停", "Paused by deletion protection"), "待确认", tone="warning", tooltip=guard_msg)
            return guard_msg

        synced_count = 0
        all_paths = sorted(set(local_notes.keys()) | set(remote_notes.keys()))
        for rel_path in all_paths:
            in_local = rel_path in local_notes
            in_remote = rel_path in remote_notes
            if in_local and not in_remote:
                text = local_notes[rel_path]
                self._write_mirror_file(mirror_dir, rel_path, text, create_only=True)
                base_map[rel_path] = sha256_text(text)
                synced_count += 1
                self._append_log(self._tr(f"推送 {rel_path}", f"Push {rel_path}"), "成功", tone="success", tooltip=self._tr(
                    "已镜像到本地目录",
                    "Copied to the local mirror",
                ))
            elif in_remote and not in_local:
                text = remote_notes[rel_path]
                bridge.call_host("host.notes.write", {"path": rel_path, "content": text})
                base_map[rel_path] = sha256_text(text)
                synced_count += 1
                self._append_log(self._tr(f"拉取 {rel_path}", f"Pull {rel_path}"), "成功", tone="success", tooltip=self._tr(
                    "已从镜像恢复",
                    "Restored from the local mirror",
                ))
            else:
                action, chosen_text, conflict_extra, new_hash = self._resolve_conflict_pair(
                    rel_path, local_notes[rel_path], remote_notes[rel_path], base_map.get(rel_path)
                )
                if action == "skip":
                    base_map[rel_path] = new_hash
                elif action == "push":
                    self._write_mirror_file(
                        mirror_dir, rel_path, chosen_text, expected_hash=sha256_text(remote_notes[rel_path])
                    )
                    base_map[rel_path] = new_hash
                    synced_count += 1
                    self._append_log(self._tr(f"本地覆盖 {rel_path}", f"Overwrite remote: {rel_path}"), "成功", tone="success", tooltip=self._tr(
                        "本地优先覆盖镜像",
                        "Local version replaced the mirrored copy",
                    ))
                elif action == "pull":
                    bridge.call_host("host.notes.write", {"path": rel_path, "content": chosen_text})
                    base_map[rel_path] = new_hash
                    synced_count += 1
                    self._append_log(self._tr(f"远端覆盖 {rel_path}", f"Overwrite local: {rel_path}"), "成功", tone="success", tooltip=self._tr(
                        "镜像优先更新本地",
                        "Mirrored version replaced the local copy",
                    ))
                elif action == "keep_both":
                    conflict_rel, conflict_text = conflict_extra
                    bridge.call_host("host.notes.write", {"path": conflict_rel, "content": conflict_text})
                    self._write_mirror_file(mirror_dir, conflict_rel, conflict_text, create_only=True)
                    self._write_mirror_file(
                        mirror_dir, rel_path, chosen_text, expected_hash=sha256_text(remote_notes[rel_path])
                    )
                    base_map[rel_path] = new_hash
                    base_map[conflict_rel] = sha256_text(conflict_text)
                    synced_count += 1
                    self._append_log(self._tr(f"冲突保留 {rel_path}", f"Keep conflict copy: {rel_path}"), "冲突副本", tone="warning", tooltip=self._tr(
                        f"已保留副本 {conflict_rel}",
                        f"Saved a copy at {conflict_rel}",
                    ))

        try:
            asset_count = self._sync_local_dir_assets(mirror_dir, base_map=base_map)
        except Exception:
            self.sync_meta[meta_key] = base_map
            try:
                bridge.call_host("host.storage.set", {"key": "sync_meta", "value": self.sync_meta})
            except Exception:
                pass
            raise
        if asset_count > 0:
            self._append_log(self._tr(f"同步 {asset_count} 个附件", f"Synced attachments: {asset_count}"), "成功", tone="success")

        self.sync_meta[meta_key] = base_map
        self.stats["total_synced"] += synced_count
        self.stats["last_sync"] = now_hms()
        if synced_count == 0 and asset_count == 0 and not all_paths:
            return self._tr("当前笔记本暂无笔记", "This notebook has no notes")
        if synced_count == 0 and asset_count == 0:
            return self._tr("目录镜像已是最新，无需更新", "The local mirror is up to date")
        if asset_count > 0:
            return self._tr(
                f"已完成目录镜像同步，处理 {synced_count} 篇笔记、{asset_count} 个附件",
                f"Local mirror sync complete. Notes: {synced_count}. Attachments: {asset_count}.",
            )
        return self._tr(f"已完成目录镜像同步，处理 {synced_count} 篇笔记", f"Local mirror sync complete. Notes: {synced_count}.")

    # ---------- WebDAV Mode ----------

    def _webdav_headers(self, extra=None, cfg=None):
        c = cfg or self.config
        headers = {"User-Agent": "block-sync/1.0"}
        user = str(c.get("webdav_user") or "").strip()
        passwd = str(c.get("webdav_pass") or "")
        if user and passwd:
            encoded = base64.b64encode(f"{user}:{passwd}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        elif user:
            encoded = base64.b64encode(f"{user}:".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        elif passwd.strip():
            token = passwd.strip()
            if token.lower().startswith("bearer ") or token.lower().startswith("basic "):
                headers["Authorization"] = token
            elif ":" in token:
                encoded = base64.b64encode(token.encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {encoded}"
            else:
                headers["Authorization"] = f"Bearer {token}"
        if extra:
            headers.update(extra)
        return headers

    def _webdav_root_url(self, cfg=None):
        c = cfg or self.config
        url = str(c.get("webdav_url") or "").strip()
        if not url:
            return ""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return ""
        return url.rstrip("/") + "/"

    def _webdav_base_url(self, cfg=None, subdir=""):
        root = self._webdav_root_url(cfg)
        if not root:
            return ""
        sub = self._resolve_webdav_dir(cfg).strip().strip("/")
        parts = [urllib.parse.quote(p) for p in sub.split("/") if p and p not in (".", "..")] if sub else []
        if subdir:
            parts.extend(urllib.parse.quote(p) for p in subdir.strip("/").split("/") if p and p not in (".", ".."))
        if not parts:
            return root
        return root + "/".join(parts) + "/"

    def _webdav_request(self, method, url, body=None, extra_headers=None, timeout=6, cfg=None):
        req = urllib.request.Request(
            url,
            data=body,
            headers=self._webdav_headers(extra_headers, cfg=cfg),
            method=method,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()

    def _webdav_ensure_dir(self, root_url, dir_rel, cfg=None):
        parts = [p for p in dir_rel.strip("/").split("/") if p and p not in (".", "..")]
        cur = root_url
        for part in parts:
            cur = cur + urllib.parse.quote(part) + "/"
            try:
                self._webdav_request("MKCOL", cur, cfg=cfg)
            except urllib.error.HTTPError as exc:
                if exc.code not in (405, 301, 302, 409):
                    raise

    def _test_webdav(self):
        root_url = self._webdav_root_url()
        base_url = self._webdav_base_url()
        if not root_url or not base_url:
            return False, self._tr("请填写有效的 WebDAV http(s) 地址", "Enter a valid HTTP or HTTPS WebDAV address")
        try:
            status, _ = self._webdav_request("PROPFIND", base_url, extra_headers={"Depth": "0"})
            if status in (200, 204, 207):
                return True, self._tr(f"WebDAV 连接正常 (HTTP {status})", f"WebDAV connection successful (HTTP {status})")
            return False, self._tr(f"WebDAV 响应异常 (HTTP {status})", f"Unexpected WebDAV response (HTTP {status})")
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and base_url != root_url:
                try:
                    status, _ = self._webdav_request("PROPFIND", root_url, extra_headers={"Depth": "0"})
                    if status in (200, 204, 207):
                        return True, self._tr("WebDAV 连通正常（远端目录将在同步时创建）", "WebDAV connection successful. The remote folder will be created during sync.")
                except Exception:
                    pass
            if exc.code in (401, 403):
                return False, self._tr(f"WebDAV 认证失败 (HTTP {exc.code})", f"WebDAV authentication failed (HTTP {exc.code})")
            return False, self._tr(f"WebDAV 请求失败 (HTTP {exc.code})", f"WebDAV request failed (HTTP {exc.code})")
        except Exception as exc:
            return False, self._tr(f"WebDAV 连接不可达: {self._error_detail(exc)}", f"WebDAV server is unreachable: {self._error_detail(exc)}")

    def _webdav_list_files(self, base_url, filter_fn, cfg=None, timeout=6, excluded_subdirs=(), skip_assets=False):
        root_parsed = urllib.parse.urlparse(base_url)
        root_path = urllib.parse.unquote(root_parsed.path).rstrip("/") + "/"
        if not root_path.startswith("/"):
            root_path = "/" + root_path
        queue = [base_url if base_url.endswith("/") else base_url + "/"]
        visited = set()
        items = []
        max_dirs = 200

        while queue:
            dir_url = queue.pop(0)
            dir_parsed = urllib.parse.urlparse(dir_url)
            dir_path = urllib.parse.unquote(dir_parsed.path).rstrip("/") + "/"
            if dir_path in visited:
                continue
            visited.add(dir_path)

            try:
                status, body = self._webdav_request("PROPFIND", dir_url, extra_headers={"Depth": "1"}, timeout=timeout, cfg=cfg)
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    continue
                raise
            if status not in (200, 207):
                continue

            root = ET.fromstring(body)
            responses = [elem for elem in root.iter() if elem.tag.endswith("response")]
            for resp in responses:
                href_text = ""
                is_col = False
                for child in resp.iter():
                    if child.tag.endswith("href") and child.text and not href_text:
                        href_text = child.text.strip()
                    elif child.tag.endswith("collection"):
                        is_col = True
                if not href_text:
                    continue

                abs_href = urllib.parse.urljoin(dir_url, href_text)
                href_path = urllib.parse.unquote(urllib.parse.urlparse(abs_href).path)
                norm_dir = href_path.rstrip("/") + "/"
                if norm_dir == dir_path:
                    continue
                if not href_path.startswith(root_path):
                    continue

                rel = href_path[len(root_path):].lstrip("/")
                if not rel or in_sync_subdir(rel, excluded_subdirs):
                    continue
                if is_col or href_text.endswith("/"):
                    rel_dir = rel.rstrip("/")
                    if skip_assets and "assets" in rel_dir.split("/"):
                        continue
                    if any(part.startswith(".") for part in rel_dir.split("/") if part):
                        continue
                    if norm_dir not in visited and len(visited) + len(queue) < max_dirs:
                        child_url = urllib.parse.urlunparse((
                            root_parsed.scheme,
                            root_parsed.netloc,
                            urllib.parse.quote(norm_dir, safe="/"),
                            "",
                            "",
                            "",
                        ))
                        queue.append(child_url)
                elif filter_fn(rel):
                    items.append(rel)

        return sorted(set(items))

    def _webdav_ensure_parents(self, base_url, rel_path, cfg=None):
        parts = rel_path.split("/")[:-1]
        cur = base_url
        for part in parts:
            cur = cur + urllib.parse.quote(part) + "/"
            try:
                self._webdav_request("MKCOL", cur, cfg=cfg)
            except urllib.error.HTTPError as exc:
                if exc.code not in (405, 301, 302, 409):
                    raise

    def _webdav_get_bytes(self, file_url, cfg=None, timeout=6):
        try:
            status, body = self._webdav_request("GET", file_url, timeout=timeout, cfg=cfg)
            if 200 <= status < 300:
                return True, body
            return False, b""
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False, b""
            raise

    def _webdav_put_text(self, base_url, rel_path, content, cfg=None):
        self._webdav_ensure_parents(base_url, rel_path, cfg=cfg)
        file_url = base_url + "/".join(urllib.parse.quote(p) for p in rel_path.split("/"))
        self._webdav_request(
            "PUT",
            file_url,
            body=content.encode("utf-8"),
            extra_headers={"Content-Type": "text/markdown; charset=utf-8"},
            cfg=cfg,
        )

    def _webdav_put_bytes(self, base_url, rel_path, data, cfg=None):
        self._webdav_ensure_parents(base_url, rel_path, cfg=cfg)
        file_url = base_url + "/".join(urllib.parse.quote(p) for p in rel_path.split("/"))
        self._webdav_request(
            "PUT",
            file_url,
            body=data,
            extra_headers={"Content-Type": "application/octet-stream"},
            cfg=cfg,
        )

    def _sync_webdav_assets(self, base_url, nb_root=None, paths=None, excluded_subdirs=(), cfg=None, base_map=None):
        c = cfg or self.config
        root_dir = nb_root or self.notebook_root
        if not c.get("sync_assets", True) or not root_dir:
            return 0
        candidates = self._asset_paths_for_sync(root_dir, paths, excluded_subdirs)
        if paths is None:
            candidates.update(self._webdav_list_files(
                base_url, is_safe_rel_asset, cfg=c, excluded_subdirs=excluded_subdirs,
            ))

        def read_remote(rel):
            file_url = base_url + "/".join(urllib.parse.quote(p) for p in rel.split("/"))
            found, data = self._webdav_get_bytes(file_url, cfg=c)
            return data if found else None

        return self._sync_assets(
            candidates,
            lambda rel: self._read_asset_file(root_dir, rel),
            read_remote,
            lambda rel, data: self._write_mirror_bytes(root_dir, rel, data),
            lambda rel, data: self._webdav_put_bytes(base_url, rel, data, cfg=c),
            c.get("conflict_policy", "keep_both"),
            base_map=base_map,
        )

    def _sync_webdav(self, bridge, only_path=None):
        root_url = self._webdav_root_url()
        base_url = self._webdav_base_url()
        if not root_url or not base_url:
            msg = self._tr("请先填写有效的 WebDAV http(s) 地址", "Enter a valid HTTP or HTTPS WebDAV address first")
            self._append_log(self._tr("WebDAV 同步", "WebDAV sync"), "失败", tone="danger", tooltip=msg)
            return msg

        try:
            sub_dir = self._resolve_webdav_dir().strip().strip("/")
            if sub_dir:
                self._webdav_ensure_dir(root_url, sub_dir)

            local_notes = self._read_local_notes(bridge, only_path=only_path)
            remote_paths = (
                [only_path]
                if only_path
                else [p for p in self._webdav_list_files(base_url, is_safe_rel_md) if self._matches_scope(p)]
            )
            remote_notes = {}
            for rel_path in remote_paths:
                if not is_safe_rel_md(rel_path):
                    continue
                file_url = base_url + "/".join(urllib.parse.quote(p) for p in rel_path.split("/"))
                found, raw_bytes = self._webdav_get_bytes(file_url)
                if found:
                    remote_notes[rel_path] = raw_bytes.decode("utf-8", errors="replace")

            meta_key = f"webdav:{base_url}"
            base_map = dict(self.sync_meta.get(meta_key) or {})

            guard_msg = self._check_delete_guard(base_map, local_notes, remote_notes, only_path=only_path)
            if guard_msg:
                self._append_log(self._tr("删除保护暂停", "Paused by deletion protection"), "待确认", tone="warning", tooltip=guard_msg)
                return guard_msg

            synced_count = 0
            all_paths = sorted(set(local_notes.keys()) | set(remote_notes.keys()))
            for rel_path in all_paths:
                in_local = rel_path in local_notes
                in_remote = rel_path in remote_notes
                if in_local and not in_remote:
                    text = local_notes[rel_path]
                    self._webdav_put_text(base_url, rel_path, text)
                    base_map[rel_path] = sha256_text(text)
                    synced_count += 1
                    self._append_log(self._tr(f"推送 {rel_path}", f"Push {rel_path}"), "成功", tone="success", tooltip=self._tr(
                        "已上传到 WebDAV",
                        "Uploaded to WebDAV",
                    ))
                elif in_remote and not in_local:
                    text = remote_notes[rel_path]
                    bridge.call_host("host.notes.write", {"path": rel_path, "content": text})
                    base_map[rel_path] = sha256_text(text)
                    synced_count += 1
                    self._append_log(self._tr(f"拉取 {rel_path}", f"Pull {rel_path}"), "成功", tone="success", tooltip=self._tr(
                        "已从 WebDAV 下载",
                        "Downloaded from WebDAV",
                    ))
                else:
                    action, chosen_text, conflict_extra, new_hash = self._resolve_conflict_pair(
                        rel_path, local_notes[rel_path], remote_notes[rel_path], base_map.get(rel_path)
                    )
                    if action == "skip":
                        base_map[rel_path] = new_hash
                    elif action == "push":
                        self._webdav_put_text(base_url, rel_path, chosen_text)
                        base_map[rel_path] = new_hash
                        synced_count += 1
                        self._append_log(self._tr(f"本地覆盖 {rel_path}", f"Overwrite remote: {rel_path}"), "成功", tone="success", tooltip=self._tr(
                            "本地优先上传 WebDAV",
                            "Local version replaced the WebDAV copy",
                        ))
                    elif action == "pull":
                        bridge.call_host("host.notes.write", {"path": rel_path, "content": chosen_text})
                        base_map[rel_path] = new_hash
                        synced_count += 1
                        self._append_log(self._tr(f"远端覆盖 {rel_path}", f"Overwrite local: {rel_path}"), "成功", tone="success", tooltip=self._tr(
                            "远端优先更新本地",
                            "Remote version replaced the local copy",
                        ))
                    elif action == "keep_both":
                        conflict_rel, conflict_text = conflict_extra
                        bridge.call_host("host.notes.write", {"path": conflict_rel, "content": conflict_text})
                        self._webdav_put_text(base_url, conflict_rel, conflict_text)
                        self._webdav_put_text(base_url, rel_path, chosen_text)
                        base_map[rel_path] = new_hash
                        base_map[conflict_rel] = sha256_text(conflict_text)
                        synced_count += 1
                        self._append_log(self._tr(f"冲突保留 {rel_path}", f"Keep conflict copy: {rel_path}"), "冲突副本", tone="warning", tooltip=self._tr(
                            f"WebDAV 冲突已保留副本 {conflict_rel}",
                            f"Saved a WebDAV conflict copy at {conflict_rel}",
                        ))

            asset_count = 0 if only_path else self._sync_webdav_assets(base_url, base_map=base_map)
            if asset_count > 0:
                self._append_log(self._tr(f"同步 {asset_count} 个附件", f"Synced attachments: {asset_count}"), "成功", tone="success")

            self.sync_meta[meta_key] = base_map
            self.stats["total_synced"] += synced_count
            self.stats["last_sync"] = now_hms()
            if synced_count == 0 and asset_count == 0:
                return self._tr("WebDAV 已是最新状态", "WebDAV is up to date")
            if asset_count > 0:
                return self._tr(
                    f"已完成 WebDAV 同步，处理 {synced_count} 篇笔记、{asset_count} 个附件",
                    f"WebDAV sync complete. Notes: {synced_count}. Attachments: {asset_count}.",
                )
            return self._tr(f"已完成 WebDAV 同步，处理 {synced_count} 篇笔记", f"WebDAV sync complete. Notes: {synced_count}.")
        except Exception as exc:
            msg = self._tr(f"WebDAV 同步未完成: {self._error_detail(exc)}", f"WebDAV sync failed: {self._error_detail(exc)}")
            self._append_log(self._tr("WebDAV 同步", "WebDAV sync"), "失败", tone="danger", tooltip=msg)
            return msg

    # ---------- Git Mode ----------

    def _is_remote_git_url(self, target):
        lower = target.lower()
        return (
            lower.startswith("https://")
            or lower.startswith("http://")
            or lower.startswith("ssh://")
            or lower.startswith("git@")
            or lower.startswith("file://")
        )

    def _git_branch(self, cfg=None):
        c = cfg or self.config
        return str(c.get("git_branch") or "").strip() or "main"

    def _git_env(self):
        env = dict(os.environ)
        env["GIT_TERMINAL_PROMPT"] = "0"
        if self._is_en():
            env["LC_ALL"] = "C"
        return env

    def _run_git(self, args, cwd=None, timeout=8, cfg=None):
        c = cfg or self.config
        cmd = ["git"]
        auth_mode = c.get("git_auth", "ssh")
        token = str(c.get("git_token") or "").strip()
        target = str(c.get("git_remote") or "").strip()
        if auth_mode == "token" and token and target.lower().startswith(("https://", "http://")):
            encoded = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
            cmd.extend(["-c", f"http.extraHeader=Authorization: Basic {encoded}"])
        cmd.extend(args)
        return subprocess.run(
            cmd,
            cwd=cwd,
            env=self._git_env(),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def _git_repo_dirs(self, cfg):
        target = str(cfg.get("git_remote") or "").strip()
        if target and not self._is_remote_git_url(target):
            expanded = os.path.expanduser(target)
            base = self.data_dir or os.getcwd()
            path = os.path.normpath(os.path.join(base, expanded))
            return [path]
        base = os.path.join(self.data_dir or os.getcwd(), "git-repos")
        if not target:
            return [os.path.join(base, self._notebook_slug())]

        canonical = os.path.join(base, f"repo-{sha256_text(target)[:12]}")
        legacy = []
        if os.path.isdir(base) and shutil.which("git"):
            for name in sorted(os.listdir(base)):
                path = os.path.join(base, name)
                if path == canonical or not re.search(r"-[0-9a-f]{8}$", name):
                    continue
                if not os.path.isdir(os.path.join(path, ".git")):
                    continue
                result = self._run_git(["config", "--local", "--get", "remote.origin.url"], cwd=path, cfg=cfg)
                if result.returncode == 0 and result.stdout.strip() == target:
                    legacy.append(path)
        return [canonical, *legacy]

    def _resolve_local_git_dir(self, cfg=None):
        dirs = self._git_repo_dirs(cfg or self.config)
        return next((path for path in dirs if os.path.isdir(os.path.join(path, ".git"))), dirs[0])

    def _sync_target_base(self, cfg):
        protocol = cfg["protocol"]
        if protocol == "local_mirror":
            return self._resolve_mirror_dir(cfg)
        if protocol == "webdav":
            return self._webdav_base_url(cfg) or "unconfigured"
        return f"{self._resolve_local_git_dir(cfg)}:{self._git_branch(cfg)}"

    def _is_transient_git_error(self, raw_text):
        lower = str(raw_text or "").lower()
        if not lower:
            return False
        non_transient = (
            "permission denied (publickey)",
            "authentication failed",
            "invalid username or token",
            "invalid username or password",
            "http basic: access denied",
            "repository not found",
            "could not read username",
            "terminal prompts disabled",
            "returned error: 401",
            "returned error: 403",
            "returned error: 404",
            "non-fast-forward",
            "could not apply",
        )
        if any(token in lower for token in non_transient):
            return False
        transient = (
            "connection closed",
            "connection reset",
            "broken pipe",
            "timed out",
            "timeout",
            "could not resolve host",
            "temporary failure in name resolution",
            "failed to connect",
            "couldn't connect to server",
            "network is unreachable",
            "no route to host",
            "connection refused",
            "unexpected disconnect",
            "early eof",
            "the remote end hung up unexpectedly",
            "kex_exchange_identification",
            "banner exchange",
            "recv failure",
            "empty reply from server",
            "ssl_connect",
            "gnutls_handshake",
            "curl 7",
            "curl 28",
            "curl 35",
            "curl 56",
        )
        return any(token in lower for token in transient)

    def _git_error_message(self, raw_text, fallback):
        lower = str(raw_text or "").lower()
        if "permission denied (publickey)" in lower:
            return self._tr(
                "SSH 公钥认证失败，请检查本机 SSH 密钥配置",
                "SSH public key authentication failed; check your SSH key setup",
            )
        if any(token in lower for token in (
            "authentication failed",
            "invalid username or token",
            "invalid username or password",
            "http basic: access denied",
            "returned error: 401",
            "returned error: 403",
            "could not read username",
            "terminal prompts disabled",
        )):
            return self._tr(
                "身份认证失败，请检查访问令牌或仓库权限",
                "Authentication failed; check your access token or repository permissions",
            )
        if any(token in lower for token in ("repository not found", "returned error: 404")):
            return self._tr(
                "未找到远端仓库，请检查仓库地址和访问权限",
                "Remote repository not found; check the URL and access permissions",
            )
        if any(token in lower for token in ("timed out", "timeout", "curl 28")):
            return self._tr(
                "连接超时，请检查网络或代理设置后重试",
                "Connection timed out; check your network or proxy and try again",
            )
        if any(token in lower for token in (
            "connection closed",
            "connection reset",
            "broken pipe",
            "kex_exchange_identification",
            "banner exchange",
            "early eof",
            "unexpected disconnect",
            "the remote end hung up unexpectedly",
            "recv failure",
            "empty reply from server",
        )):
            return self._tr(
                "网络连接中断，请检查网络或代理后重试",
                "Network connection was closed; check your network or proxy and try again",
            )
        if any(token in lower for token in (
            "could not resolve host",
            "temporary failure in name resolution",
            "failed to connect",
            "couldn't connect to server",
            "network is unreachable",
            "no route to host",
            "connection refused",
            "ssl_connect",
            "gnutls_handshake",
            "curl 7",
            "curl 35",
            "curl 56",
        )):
            return self._tr(
                "无法连接远端服务器，请检查网络或代理设置",
                "Could not reach the remote server; check your network or proxy",
            )
        return self._error_detail(raw_text or fallback)

    def _run_git_network(
        self,
        args,
        cwd=None,
        timeout=12,
        cfg=None,
        retries=2,
        retry_delay=1.0,
        total_budget=22.0,
        on_retry=None,
    ):
        started = time.monotonic()
        last_proc = None
        for attempt in range(retries + 1):
            elapsed = time.monotonic() - started
            if attempt > 0:
                remaining = total_budget - elapsed
                if remaining <= 2.0:
                    break
                step_timeout = min(timeout, max(3.0, remaining))
            else:
                step_timeout = timeout
            try:
                proc = self._run_git(args, cwd=cwd, timeout=step_timeout, cfg=cfg)
            except subprocess.TimeoutExpired:
                proc = subprocess.CompletedProcess(
                    ["git", *args],
                    124,
                    "",
                    f"Connection timed out after {int(step_timeout)}s",
                )
            last_proc = proc
            if proc.returncode == 0:
                return proc
            raw_err = proc.stderr or proc.stdout or ""
            if attempt >= retries or not self._is_transient_git_error(raw_err):
                return proc
            delay = min(retry_delay * (attempt + 1), 2.5)
            if (time.monotonic() - started) + delay + 2.0 >= total_budget:
                return proc
            if on_retry is not None:
                try:
                    on_retry()
                except Exception:
                    pass
            time.sleep(delay)
        return last_proc

    def _test_git(self):
        if not shutil.which("git"):
            return False, self._tr("当前环境未安装 git 命令", "Git is not installed")
        target = self.config.get("git_remote", "").strip()
        branch = self._git_branch()
        try:
            if target and self._is_remote_git_url(target):
                proc = self._run_git_network(
                    ["ls-remote", "--heads", target, branch],
                    timeout=10,
                    retries=1,
                    total_budget=20.0,
                )
                if proc.returncode == 0:
                    return True, self._tr(f"Git 远端仓库连接正常（分支 {branch}）", f"Git remote connection successful (branch: {branch})")
                err = self._git_error_message(proc.stderr or proc.stdout, self._tr("连接失败", "Connection failed"))
                return False, self._tr(f"Git 远端不可达: {err}", f"Git remote is unreachable: {err}")

            repo_dir = self._resolve_local_git_dir()
            if not os.path.isdir(repo_dir):
                return False, self._tr(f"本地 Git 仓库目录不存在: {repo_dir}", f"Local Git repository folder does not exist: {repo_dir}")
            proc = self._run_git(["rev-parse", "--is-inside-work-tree"], cwd=repo_dir)
            if proc.returncode != 0 or proc.stdout.strip() != "true":
                return False, self._tr(f"目录不是有效的 Git 仓库: {repo_dir}", f"Folder is not a valid Git repository: {repo_dir}")
            remote_proc = self._run_git(["remote"], cwd=repo_dir)
            remotes = [r.strip() for r in remote_proc.stdout.splitlines() if r.strip()]
            if remotes:
                ls_proc = self._run_git_network(
                    ["ls-remote", "--heads", remotes[0], branch],
                    cwd=repo_dir,
                    timeout=10,
                    retries=1,
                    total_budget=20.0,
                )
                if ls_proc.returncode == 0:
                    return True, self._tr(f"Git 仓库及远端 {remotes[0]} 正常", f"Git repository and remote {remotes[0]} are available")
                return True, self._tr(f"本地 Git 仓库可用（远端 {remotes[0]} 当前离线）", f"Local Git repository is available (remote {remotes[0]} is offline)")
            return True, self._tr(f"本地 Git 仓库可用: {repo_dir}", f"Local Git repository is available: {repo_dir}")
        except Exception as exc:
            return False, self._tr(f"Git 检测异常: {self._error_detail(exc)}", f"Git connection test failed: {self._error_detail(exc)}")

    def _prepare_git_repo(self, cfg, allow_init_or_clone=True, allow_pull=True, repo_dir=None):
        if not shutil.which("git"):
            return False, self._tr("当前环境未安装 git 命令", "Git is not installed")
        target = str(cfg.get("git_remote") or "").strip()
        branch = self._git_branch(cfg)
        repo_dir = repo_dir or self._resolve_local_git_dir(cfg)

        if target and self._is_remote_git_url(target):
            if not os.path.isdir(os.path.join(repo_dir, ".git")):
                if not allow_init_or_clone:
                    return False, None
                os.makedirs(os.path.dirname(repo_dir), exist_ok=True)
                existed_before = os.path.exists(repo_dir)

                def _cleanup_partial_clone():
                    if not existed_before and os.path.exists(repo_dir):
                        shutil.rmtree(repo_dir, ignore_errors=True)

                clone_proc = self._run_git_network(
                    ["clone", "--branch", branch, target, repo_dir],
                    timeout=15,
                    cfg=cfg,
                    retries=2,
                    total_budget=30.0,
                    on_retry=_cleanup_partial_clone,
                )
                if clone_proc.returncode != 0:
                    first_err = clone_proc.stderr or clone_proc.stdout or ""
                    if not self._is_transient_git_error(first_err):
                        _cleanup_partial_clone()
                        clone_proc = self._run_git_network(
                            ["clone", target, repo_dir],
                            timeout=15,
                            cfg=cfg,
                            retries=1,
                            total_budget=24.0,
                            on_retry=_cleanup_partial_clone,
                        )
                if clone_proc.returncode != 0:
                    _cleanup_partial_clone()
                    err = self._git_error_message(clone_proc.stderr or clone_proc.stdout, self._tr("clone 失败", "Clone failed"))
                    return False, self._tr(f"Git 远端不可达: {err}", f"Git remote is unreachable: {err}")
            else:
                url_proc = self._run_git(["remote", "get-url", "origin"], cwd=repo_dir, cfg=cfg)
                if url_proc.returncode == 0 and url_proc.stdout.strip() != target:
                    self._run_git(["remote", "set-url", "origin", target], cwd=repo_dir, cfg=cfg)
                if allow_pull:
                    pull_proc = self._run_git_network(
                        ["pull", "--rebase", "--autostash", "origin", branch],
                        cwd=repo_dir,
                        timeout=12,
                        cfg=cfg,
                        retries=2,
                        total_budget=22.0,
                        on_retry=lambda: self._run_git(["rebase", "--abort"], cwd=repo_dir, cfg=cfg),
                    )
                    if pull_proc.returncode != 0:
                        err_lower = (pull_proc.stderr or pull_proc.stdout or "").lower()
                        self._run_git(["rebase", "--abort"], cwd=repo_dir, cfg=cfg)
                        if (
                            "couldn't find remote ref" not in err_lower
                            and "does not have any commits" not in err_lower
                            and "no such ref" not in err_lower
                        ):
                            err = self._git_error_message(pull_proc.stderr or pull_proc.stdout, self._tr("pull 失败", "Pull failed"))
                            return False, self._tr(f"Git 拉取失败: {err}", f"Git pull failed: {err}")
        else:
            if not os.path.isdir(os.path.join(repo_dir, ".git")):
                if not allow_init_or_clone:
                    return False, None
                os.makedirs(repo_dir, exist_ok=True)
                init_proc = self._run_git(["init", "-b", branch], cwd=repo_dir, cfg=cfg)
                if init_proc.returncode != 0:
                    init_proc = self._run_git(["init"], cwd=repo_dir, cfg=cfg)
                if init_proc.returncode != 0:
                    return False, self._tr("Git 仓库初始化失败", "Could not initialize the Git repository")

        return True, repo_dir

    def _fetch_webdav_notes(self, cfg, only_path=None, scope="all", timeout=6, force_refresh=False, subdir="", excluded_subdirs=()):
        root_url = self._webdav_root_url(cfg)
        base_url = self._webdav_base_url(cfg, subdir=subdir)
        if not root_url or not base_url:
            return False, {}, self._tr("请先填写有效的 WebDAV http(s) 地址", "Enter a valid HTTP or HTTPS WebDAV address first")

        cache_key = (base_url, scope, only_path or "", frozenset(excluded_subdirs))
        if not force_refresh and only_path is None and cache_key in self._remote_preview_cache:
            cached_ts, cached_notes = self._remote_preview_cache[cache_key]
            if time.time() - cached_ts < 15.0:
                return True, dict(cached_notes), None

        try:
            remote_paths = (
                [only_path]
                if only_path
                else [
                    p for p in self._webdav_list_files(
                        base_url, is_safe_rel_md, cfg=cfg, timeout=timeout,
                        excluded_subdirs=excluded_subdirs, skip_assets=True,
                    )
                    if self._matches_scope(p, scope)
                ]
            )
            remote_notes = {}
            for rel_path in remote_paths:
                if not is_safe_rel_md(rel_path) or is_safe_rel_asset(rel_path) or in_sync_subdir(rel_path, excluded_subdirs):
                    continue
                file_url = base_url + "/".join(urllib.parse.quote(p) for p in rel_path.split("/"))
                found, raw_bytes = self._webdav_get_bytes(file_url, cfg=cfg, timeout=timeout)
                if found:
                    remote_notes[rel_path] = raw_bytes.decode("utf-8", errors="replace")
            if only_path is None:
                self._remote_preview_cache[cache_key] = (time.time(), dict(remote_notes))
            return True, remote_notes, None
        except Exception as exc:
            return False, {}, self._tr(f"WebDAV 连接不可达: {self._error_detail(exc)}", f"WebDAV server is unreachable: {self._error_detail(exc)}")

    def _compute_sync_plan(
        self,
        bridge,
        cfg,
        only_path=None,
        inspect_remote=True,
        force_refresh=False,
        nb_root=None,
        subdir="",
        prepared_repo_dir=None,
        target_bases=(),
        excluded_subdirs=(),
    ):
        nb_key = self._notebook_key(nb_root)
        nb_label = self._notebook_label(nb_root)
        protocol = cfg.get("protocol", "local_mirror")
        scope = cfg.get("sync_scope", "all")
        policy = cfg.get("conflict_policy", "keep_both")
        local_notes = self._read_local_notes(bridge, only_path=only_path, scope=scope, nb_root=nb_root)
        for rel_path in local_notes:
            if in_sync_subdir(rel_path, excluded_subdirs):
                raise RuntimeError(self._tr(f"笔记路径与其他笔记本的同步目录重叠：{rel_path}", f"Note path overlaps with another notebook's sync folder: {rel_path}"))
        target_display = self._target_display(cfg)

        remote_notes = {}
        remote_inspected = True
        remote_error = None
        target_dir = ""
        repo_root = ""
        base_url = ""

        if protocol == "local_mirror":
            base_dir = self._resolve_mirror_dir(cfg)
            target_dir = os.path.join(base_dir, subdir) if subdir else base_dir
            meta_target = f"{base_dir}::{subdir}" if subdir else base_dir
            meta_key = self._meta_key("local_mirror", meta_target, nb_key=nb_key)
            legacy_key = f"local_mirror:{base_dir}" if not subdir else None
            remote_notes = self._scan_mirror_files(target_dir, only_path=only_path, scope=scope, excluded_subdirs=excluded_subdirs)
        elif protocol == "webdav":
            root_base_url = self._webdav_base_url(cfg)
            base_url = self._webdav_base_url(cfg, subdir=subdir)
            meta_target = f"{root_base_url}::{subdir}" if (root_base_url and subdir) else (root_base_url or "unconfigured")
            meta_key = self._meta_key("webdav", meta_target, nb_key=nb_key)
            legacy_key = f"webdav:{root_base_url}" if (root_base_url and not subdir) else None
            if not base_url:
                remote_inspected = False
                remote_error = self._tr("请先填写有效的 WebDAV http(s) 地址", "Enter a valid HTTP or HTTPS WebDAV address first")
            elif inspect_remote or force_refresh:
                ok, fetched, err = self._fetch_webdav_notes(
                    cfg,
                    only_path=only_path,
                    scope=scope,
                    timeout=6 if inspect_remote else 4,
                    force_refresh=force_refresh,
                    subdir=subdir,
                    excluded_subdirs=excluded_subdirs,
                )
                if ok:
                    remote_notes = fetched
                else:
                    remote_inspected = False
                    remote_error = err
            else:
                cache_key = (base_url, scope, only_path or "", frozenset(excluded_subdirs))
                if cache_key in self._remote_preview_cache:
                    _, cached_notes = self._remote_preview_cache[cache_key]
                    remote_notes = dict(cached_notes)
                else:
                    remote_inspected = False
        else:
            branch = self._git_branch(cfg)
            repo_dir = prepared_repo_dir or self._resolve_local_git_dir(cfg)
            repo_root = repo_dir
            target_dir = os.path.join(repo_dir, subdir) if subdir else repo_dir
            meta_target = f"{repo_dir}:{branch}::{subdir}" if subdir else f"{repo_dir}:{branch}"
            meta_key = self._meta_key("git", meta_target, nb_key=nb_key)
            legacy_key = f"git:{repo_dir}:{branch}" if not subdir else None
            if prepared_repo_dir:
                remote_notes = self._scan_mirror_files(target_dir, only_path=only_path, scope=scope, excluded_subdirs=excluded_subdirs)
            elif inspect_remote:
                ok, res = self._prepare_git_repo(cfg, allow_init_or_clone=True, allow_pull=True)
                if ok:
                    repo_root = res
                    target_dir = os.path.join(res, subdir) if subdir else res
                    remote_notes = self._scan_mirror_files(target_dir, only_path=only_path, scope=scope, excluded_subdirs=excluded_subdirs)
                else:
                    remote_inspected = False
                    remote_error = res
            elif os.path.isdir(os.path.join(repo_dir, ".git")):
                remote_notes = self._scan_mirror_files(target_dir, only_path=only_path, scope=scope, excluded_subdirs=excluded_subdirs)
            else:
                remote_inspected = False

        aliases = [
            self._meta_key(protocol, f"{base}::{subdir}" if subdir else base, nb_key=nb_key)
            for base in target_bases
        ]
        legacy_aliases = [f"{protocol}:{base}" for base in target_bases] if not subdir else []
        base_map = self._get_base_map(meta_key, *aliases, legacy_key, *legacy_aliases)
        is_first_sync = len(base_map) == 0

        to_push_new = []
        to_push_overwrite = []
        to_pull_new = []
        to_pull_overwrite = []
        conflicts = []
        synced = []

        if remote_inspected:
            all_paths = sorted(set(local_notes.keys()) | set(remote_notes.keys()))
            for rel_path in all_paths:
                in_local = rel_path in local_notes
                in_remote = rel_path in remote_notes
                if in_local and not in_remote:
                    to_push_new.append(rel_path)
                elif in_remote and not in_local:
                    to_pull_new.append(rel_path)
                else:
                    action, _, conflict_extra, _ = self._resolve_conflict_pair(
                        rel_path,
                        local_notes[rel_path],
                        remote_notes[rel_path],
                        base_map.get(rel_path),
                        policy=policy,
                    )
                    if action == "push":
                        to_push_overwrite.append(rel_path)
                    elif action == "pull":
                        to_pull_overwrite.append(rel_path)
                    elif action == "keep_both":
                        conflict_rel, _ = conflict_extra
                        conflicts.append((rel_path, conflict_rel, remote_notes[rel_path]))
                    else:
                        synced.append(rel_path)

        remote_missing = [
            p for p in base_map
            if is_safe_rel_md(p) and self._matches_scope(p, scope) and p in local_notes and p not in remote_notes
        ] if (remote_inspected and only_path is None) else []
        local_missing = [
            p for p in base_map
            if is_safe_rel_md(p) and self._matches_scope(p, scope) and p in remote_notes and p not in local_notes
        ] if (remote_inspected and only_path is None) else []

        local_hashes = {p: sha256_text(local_notes[p]) for p in sorted(local_notes)}
        remote_hashes = {p: sha256_text(remote_notes[p]) for p in sorted(remote_notes)}
        base_hashes = {
            p: base_map[p]
            for p in sorted(base_map)
            if p in local_notes or p in remote_notes
        }
        fp_payload = json.dumps({
            "nb": nb_key,
            "subdir": subdir,
            "excluded_subdirs": sorted(excluded_subdirs),
            "protocol": protocol,
            "target": target_display,
            "scope": scope,
            "policy": policy,
            "push_new": to_push_new,
            "push_ow": to_push_overwrite,
            "pull_new": to_pull_new,
            "pull_ow": to_pull_overwrite,
            "conflicts": [c[0] for c in conflicts],
            "remote_missing": remote_missing,
            "local_missing": local_missing,
            "local_hashes": local_hashes,
            "remote_hashes": remote_hashes,
            "base_hashes": base_hashes,
        }, sort_keys=True, ensure_ascii=False)

        return {
            "cfg": dict(cfg),
            "nb_root": nb_root or self.notebook_root,
            "nb_key": nb_key,
            "nb_label": nb_label,
            "subdir": subdir,
            "excluded_subdirs": excluded_subdirs,
            "protocol": protocol,
            "target_display": target_display,
            "target_dir": target_dir,
            "repo_root": repo_root,
            "base_url": base_url,
            "meta_key": meta_key,
            "base_map": base_map,
            "is_first_sync": is_first_sync,
            "local_notes": local_notes,
            "remote_notes": remote_notes,
            "remote_inspected": remote_inspected,
            "remote_error": remote_error,
            "to_push_new": to_push_new,
            "to_push_overwrite": to_push_overwrite,
            "to_pull_new": to_pull_new,
            "to_pull_overwrite": to_pull_overwrite,
            "conflicts": conflicts,
            "synced": synced,
            "remote_missing": remote_missing,
            "local_missing": local_missing,
            "policy": policy,
            "scope": scope,
            "fingerprint": sha256_text(fp_payload),
        }

    def _assess_dangerous_changes(self, plan, cfg, saved_path=None):
        if not plan.get("remote_inspected"):
            return []
        reasons = []
        policy = plan.get("policy") or cfg.get("conflict_policy", "keep_both")
        base_map = plan["base_map"]
        local_notes = plan["local_notes"]
        remote_notes = plan["remote_notes"]

        n_pull_new = len(plan["to_pull_new"])
        n_pull_total = len(plan["to_pull_overwrite"])
        n_pull_conflict = sum(
            base_map.get(path) != sha256_text(local_notes[path])
            for path in plan["to_pull_overwrite"]
        )
        n_push_conflict = sum(
            base_map.get(path) != sha256_text(remote_notes[path])
            for path in plan["to_push_overwrite"]
        )
        n_conf = len(plan["conflicts"])
        n_rm_miss = len(plan["remote_missing"])
        n_loc_miss = len(plan["local_missing"])

        if plan["is_first_sync"] and (n_pull_new > 0 or n_pull_conflict > 0 or n_push_conflict > 0 or n_conf > 0):
            reasons.append(
                self._tr(
                    f"首次同步且远端已有内容（拉取 {n_pull_new} · 覆盖本地 {n_pull_conflict} · 覆盖远端 {n_push_conflict} · 冲突 {n_conf}）",
                    f"The remote already contains notes on first sync (pull: {n_pull_new}, overwrite local: {n_pull_conflict}, overwrite remote: {n_push_conflict}, conflicts: {n_conf})",
                )
            )
        elif not plan["is_first_sync"]:
            # Clean fast-forward updates (only one side changed since base) never require confirmation.
            # Genuine conflicts follow the user's explicit conflict_policy unless they hit the bulk threshold.
            if n_pull_conflict > 0 and (policy != "remote_first" or n_pull_conflict > DELETE_GUARD_THRESHOLD):
                reasons.append(self._tr(
                    f"远端内容将覆盖本地 {n_pull_conflict} 篇冲突笔记",
                    f"Remote content will overwrite {n_pull_conflict} conflicting local notes",
                ))
            if n_push_conflict > 0 and (policy != "local_first" or n_push_conflict > DELETE_GUARD_THRESHOLD):
                reasons.append(self._tr(
                    f"本地内容将覆盖远端 {n_push_conflict} 篇冲突笔记",
                    f"Local content will overwrite {n_push_conflict} conflicting remote notes",
                ))
        if cfg.get("delete_guard", True) and (n_rm_miss > DELETE_GUARD_THRESHOLD or n_loc_miss > DELETE_GUARD_THRESHOLD):
            reasons.append(
                self._tr(
                    f"触发批量缺失保护（远端缺失 {n_rm_miss} 篇 / 本地缺失 {n_loc_miss} 篇，阈值 {DELETE_GUARD_THRESHOLD}）",
                    f"Deletion protection triggered (missing remotely: {n_rm_miss}, missing locally: {n_loc_miss}, limit: {DELETE_GUARD_THRESHOLD})",
                )
            )
        elif n_pull_new + n_pull_total > DELETE_GUARD_THRESHOLD:
            reasons.append(self._tr(
                f"将向本地批量写入 {n_pull_new + n_pull_total} 篇笔记（超 {DELETE_GUARD_THRESHOLD} 篇）",
                f"Bulk write to local notes: {n_pull_new + n_pull_total} (limit: {DELETE_GUARD_THRESHOLD})",
            ))
        return reasons

    def _commit_and_push_git(self, repo_root, cfg):
        # Remove any stale untracked atomic-write temp files left behind by a prior SIGKILL cancellation
        # so they can never be staged or pushed to the remote repository.
        self._cleanup_stale_temp_files(repo_root, cfg=cfg)
        branch = self._git_branch(cfg)
        status_proc = self._run_git(["status", "--porcelain"], cwd=repo_root, cfg=cfg)
        if status_proc.returncode != 0:
            err = self._error_detail(status_proc.stderr or status_proc.stdout or self._tr("git status 失败", "git status failed"))
            raise RuntimeError(self._tr(f"Git 状态检查失败: {err}", f"Git status check failed: {err}"))

        if status_proc.stdout.strip():
            add_proc = self._run_git(["add", "-A"], cwd=repo_root, cfg=cfg)
            if add_proc.returncode != 0:
                err = self._error_detail(add_proc.stderr or add_proc.stdout or self._tr("git add 失败", "git add failed"))
                raise RuntimeError(self._tr(f"Git 暂存失败: {err}", f"Git staging failed: {err}"))

            commit_proc = self._run_git(
                [
                    "-c", "user.name=Block Sync",
                    "-c", "user.email=sync@blockmd.local",
                    "commit", "-m", "sync: update markdown notes",
                ],
                cwd=repo_root,
                cfg=cfg,
            )
            if commit_proc.returncode != 0:
                self._run_git(["reset"], cwd=repo_root, cfg=cfg)
                err = self._error_detail(commit_proc.stderr or commit_proc.stdout or self._tr("git commit 失败", "git commit failed"))
                raise RuntimeError(self._tr(f"Git 提交失败: {err}", f"Git commit failed: {err}"))

        remote_proc = self._run_git(["remote"], cwd=repo_root, cfg=cfg)
        if remote_proc.returncode != 0:
            err = self._error_detail(remote_proc.stderr or remote_proc.stdout or self._tr("git remote 失败", "git remote failed"))
            raise RuntimeError(self._tr(f"Git 远端检查失败: {err}", f"Git remote check failed: {err}"))

        remotes = [r.strip() for r in remote_proc.stdout.splitlines() if r.strip()]
        if remotes:
            remote_name = "origin" if "origin" in remotes else remotes[0]
            head_proc = self._run_git(["rev-parse", "--verify", "HEAD"], cwd=repo_root, cfg=cfg)
            if head_proc.returncode == 0:
                needs_push = False
                ref_proc = self._run_git(
                    ["rev-parse", "--verify", f"refs/remotes/{remote_name}/{branch}"],
                    cwd=repo_root,
                    cfg=cfg,
                )
                if ref_proc.returncode != 0:
                    needs_push = True
                else:
                    ahead_proc = self._run_git(
                        ["rev-list", "--count", f"refs/remotes/{remote_name}/{branch}..HEAD"],
                        cwd=repo_root,
                        cfg=cfg,
                    )
                    if ahead_proc.returncode != 0 or int((ahead_proc.stdout or "0").strip() or "0") > 0:
                        needs_push = True

                if needs_push:
                    push_proc = self._run_git_network(
                        ["push", "-u", remote_name, f"HEAD:{branch}"],
                        cwd=repo_root,
                        timeout=12,
                        cfg=cfg,
                        retries=2,
                        total_budget=22.0,
                    )
                    if push_proc.returncode != 0:
                        err = self._git_error_message(push_proc.stderr or push_proc.stdout, self._tr("push 失败", "Push failed"))
                        raise RuntimeError(self._tr(f"已提交到本地 Git，但远端推送未完成: {err}", f"Committed locally. Git push failed: {err}"))
                    return True
        return False

    def _apply_notebook_plan(self, bridge, plan, only_path=None, progress_state=None):
        protocol = plan["protocol"]
        cfg = plan["cfg"]
        nb_root = plan.get("nb_root") or self.notebook_root
        subdir = plan.get("subdir") or ""
        base_map = dict(plan["base_map"])
        local_notes = plan["local_notes"]
        remote_notes = plan["remote_notes"]
        target_dir = plan["target_dir"]
        base_url = plan["base_url"]

        if protocol == "local_mirror":
            os.makedirs(target_dir, exist_ok=True)
            write_remote = lambda rel, text, expected_hash=None, create_only=False: self._write_mirror_file(
                target_dir, rel, text, expected_hash=expected_hash, create_only=create_only,
            )
        elif protocol == "webdav":
            root_url = self._webdav_root_url(cfg)
            sub_dir = self._resolve_webdav_dir(cfg).strip().strip("/")
            full_sub = "/".join(p for p in (sub_dir, subdir.strip("/")) if p)
            if full_sub:
                self._webdav_ensure_dir(root_url, full_sub, cfg=cfg)
            write_remote = lambda rel, text, expected_hash=None, create_only=False: self._webdav_put_text(
                base_url, rel, text, cfg=cfg,
            )
        else:
            os.makedirs(target_dir, exist_ok=True)
            write_remote = lambda rel, text, expected_hash=None, create_only=False: self._write_mirror_file(
                target_dir, rel, text, expected_hash=expected_hash, create_only=create_only,
            )

        pushed = 0
        pulled = 0
        conflict_count = 0
        prefix = f"{plan.get('nb_label')}/" if subdir else ""

        def step_progress():
            if progress_state is not None and progress_state.get("total", 0) > 0:
                progress_state["done"] += 1
                self._emit_progress(bridge, done=progress_state["done"], total=progress_state["total"])

        asset_count = 0
        if cfg.get("sync_assets", True):
            paths = None
            if only_path is not None:
                paths = note_asset_paths(only_path, local_notes.get(only_path, ""))
                paths.update(note_asset_paths(only_path, remote_notes.get(only_path, "")))
                if is_safe_rel_asset(only_path):
                    paths.add(only_path)
            excluded_subdirs = plan["excluded_subdirs"]
            if protocol == "webdav":
                asset_count = self._sync_webdav_assets(
                    base_url, nb_root=nb_root, paths=paths, excluded_subdirs=excluded_subdirs, cfg=cfg, base_map=base_map,
                )
            else:
                asset_count = self._sync_local_dir_assets(
                    target_dir, nb_root=nb_root, paths=paths, excluded_subdirs=excluded_subdirs, cfg=cfg, base_map=base_map,
                )
            if asset_count > 0:
                self._append_log(self._tr(f"{prefix}同步 {asset_count} 个附件", f"{prefix}Synced attachments: {asset_count}"), "成功", tone="success")

        for rel_path in plan["synced"]:
            base_map[rel_path] = sha256_text(local_notes[rel_path])

        for rel_path in plan["to_push_new"]:
            text = local_notes[rel_path]
            write_remote(rel_path, text, create_only=True)
            base_map[rel_path] = sha256_text(text)
            pushed += 1
            self._append_log(self._tr(f"推送 {prefix}{rel_path}", f"Push {prefix}{rel_path}"), "成功", tone="success", tooltip=self._tr(
                f"已推送到{self._protocol_label(protocol)}",
                f"Pushed to {self._protocol_label(protocol)}",
            ))
            step_progress()

        for rel_path in plan["to_push_overwrite"]:
            text = local_notes[rel_path]
            exp_hash = sha256_text(remote_notes[rel_path]) if rel_path in remote_notes else None
            is_conflict = exp_hash is not None and base_map.get(rel_path) != exp_hash
            write_remote(rel_path, text, expected_hash=exp_hash)
            base_map[rel_path] = sha256_text(text)
            pushed += 1
            if is_conflict:
                self._append_log(self._tr(f"本地覆盖 {prefix}{rel_path}", f"Overwrite remote: {prefix}{rel_path}"), "成功", tone="success", tooltip=self._tr(
                    f"本地优先覆盖{self._protocol_label(protocol)}",
                    f"Local version took precedence on {self._protocol_label(protocol)}",
                ))
            else:
                self._append_log(self._tr(f"更新 {prefix}{rel_path}", f"Update {prefix}{rel_path}"), "成功", tone="success", tooltip=self._tr(
                    f"已同步修改到{self._protocol_label(protocol)}",
                    f"Synced changes to {self._protocol_label(protocol)}",
                ))
            step_progress()

        for rel_path in plan["to_pull_new"]:
            text = remote_notes[rel_path]
            self._write_local_note(bridge, rel_path, text, nb_root=nb_root)
            base_map[rel_path] = sha256_text(text)
            pulled += 1
            self._append_log(self._tr(f"拉取 {prefix}{rel_path}", f"Pull {prefix}{rel_path}"), "成功", tone="success", tooltip=self._tr(
                f"已从{self._protocol_label(protocol)}拉取",
                f"Pulled from {self._protocol_label(protocol)}",
            ))
            step_progress()

        for rel_path in plan["to_pull_overwrite"]:
            text = remote_notes[rel_path]
            local_hash = sha256_text(local_notes[rel_path])
            is_conflict = base_map.get(rel_path) != local_hash
            self._write_local_note(
                bridge, rel_path, text, nb_root=nb_root, expected_revision=local_hash
            )
            base_map[rel_path] = sha256_text(text)
            pulled += 1
            if is_conflict:
                self._append_log(self._tr(f"远端覆盖 {prefix}{rel_path}", f"Overwrite local: {prefix}{rel_path}"), "成功", tone="success", tooltip=self._tr(
                    f"{self._protocol_label(protocol)}优先更新本地",
                    f"Version from {self._protocol_label(protocol)} replaced the local copy",
                ))
            else:
                self._append_log(self._tr(f"拉取更新 {prefix}{rel_path}", f"Pull update: {prefix}{rel_path}"), "成功", tone="success", tooltip=self._tr(
                    f"已从{self._protocol_label(protocol)}拉取更新",
                    f"Pulled update from {self._protocol_label(protocol)}",
                ))
            step_progress()

        for rel_path, conflict_rel, remote_text in plan["conflicts"]:
            local_text = local_notes[rel_path]
            self._write_local_note(bridge, conflict_rel, remote_text, nb_root=nb_root)
            write_remote(conflict_rel, remote_text, create_only=True)
            write_remote(rel_path, local_text, expected_hash=sha256_text(remote_text))
            base_map[rel_path] = sha256_text(local_text)
            base_map[conflict_rel] = sha256_text(remote_text)
            conflict_count += 1
            self._append_log(self._tr(f"冲突保留 {prefix}{rel_path}", f"Keep conflict copy: {prefix}{rel_path}"), "冲突副本", tone="warning", tooltip=self._tr(
                f"已保留副本 {conflict_rel}",
                f"Saved a copy at {conflict_rel}",
            ))
            step_progress()

        self.sync_meta[plan["meta_key"]] = base_map
        return pushed, pulled, conflict_count, asset_count

    def _compute_batch_plan(self, bridge, cfg, notebooks, only_path=None, inspect_remote=True, force_refresh=False):
        protocol = cfg.get("protocol", "local_mirror")
        target_display = self._target_display(cfg)
        repo_dir = None
        if protocol == "git":
            repo_dirs = self._git_repo_dirs(cfg)
            repo_dir = next((path for path in repo_dirs if os.path.isdir(os.path.join(path, ".git"))), repo_dirs[0])
            target_bases = [f"{path}:{self._git_branch(cfg)}" for path in repo_dirs]
        else:
            target_bases = [self._sync_target_base(cfg)]

        layout_key, bindings, reserved_subdirs = self._notebook_subdir_map(
            self._selected_notebooks(cfg) or notebooks, protocol, target_bases,
        )

        prepared_repo_dir = None
        if protocol == "git" and inspect_remote:
            ok, res = self._prepare_git_repo(cfg, repo_dir=repo_dir, allow_init_or_clone=True, allow_pull=True)
            if not ok:
                return {
                    "cfg": dict(cfg),
                    "protocol": protocol,
                    "target_display": target_display,
                    "repo_root": "",
                    "plans": [],
                    "remote_error": res,
                    "fingerprint": "",
                }
            prepared_repo_dir = res

        plans = []
        for nb in notebooks:
            sub = bindings[nb]
            plan = self._compute_sync_plan(
                bridge,
                cfg,
                only_path=only_path,
                inspect_remote=inspect_remote,
                force_refresh=force_refresh,
                nb_root=nb,
                subdir=sub,
                prepared_repo_dir=prepared_repo_dir,
                target_bases=target_bases,
                excluded_subdirs=reserved_subdirs if not sub else (),
            )
            if plan.get("remote_error"):
                return {
                    "cfg": dict(cfg),
                    "protocol": protocol,
                    "target_display": target_display,
                    "repo_root": prepared_repo_dir or "",
                    "plans": plans,
                    "remote_error": plan["remote_error"],
                    "fingerprint": "",
                }
            plans.append(plan)

        fp = sha256_text(json.dumps([p["fingerprint"] for p in plans], ensure_ascii=False))
        return {
            "cfg": dict(cfg),
            "protocol": protocol,
            "target_display": target_display,
            "repo_root": prepared_repo_dir or (plans[0]["repo_root"] if plans else ""),
            "plans": plans,
            "layout_key": layout_key,
            "bindings": bindings,
            "remote_error": None,
            "fingerprint": fp,
        }

    def _execute_batch_plan(self, bridge, batch, only_path=None, report_progress=False):
        protocol = batch["protocol"]
        cfg = batch["cfg"]
        total_pushed = 0
        total_pulled = 0
        total_conflicts = 0
        total_assets = 0

        layouts = self.sync_meta.get(LAYOUTS_META_KEY, {})
        layouts = dict(layouts) if isinstance(layouts, dict) else {}
        if layouts.get(batch["layout_key"]) != batch["bindings"]:
            layouts[batch["layout_key"]] = batch["bindings"]
            updated_meta = {**self.sync_meta, LAYOUTS_META_KEY: layouts}
            bridge.call_host("host.storage.set", {"key": "sync_meta", "value": updated_meta})
            self.sync_meta = updated_meta

        total_items = sum(
            len(p["to_push_new"])
            + len(p["to_push_overwrite"])
            + len(p["to_pull_new"])
            + len(p["to_pull_overwrite"])
            + len(p["conflicts"])
            for p in batch["plans"]
        )
        progress_state = {"done": 0, "total": total_items} if (report_progress and total_items > 0) else None
        if progress_state is not None:
            self._emit_progress(bridge, done=0, total=total_items)

        for plan in batch["plans"]:
            pushed, pulled, conflicts, assets = self._apply_notebook_plan(
                bridge, plan, only_path=only_path, progress_state=progress_state
            )
            total_pushed += pushed
            total_pulled += pulled
            total_conflicts += conflicts
            total_assets += assets

        did_push = False
        if protocol == "git" and batch.get("repo_root"):
            if report_progress:
                self._emit_progress(
                    bridge,
                    done=total_items if total_items > 0 else None,
                    total=total_items if total_items > 0 else None,
                    label=self._tr("推送 Git…", "Pushing Git…"),
                )
            did_push = self._commit_and_push_git(batch["repo_root"], cfg)

        self._remote_preview_cache.clear()
        total_notes = total_pushed + total_pulled + total_conflicts
        self.stats["total_synced"] += total_notes
        self.stats["last_sync"] = now_hms()

        nb_count = len(batch["plans"])
        nb_prefix = self._tr(f"{nb_count} 个笔记本 · ", f"Notebooks: {nb_count} · ") if nb_count > 1 else ""

        if total_notes == 0 and total_assets == 0:
            if did_push:
                summary = self._tr("已将本地 Git 待推送提交同步到远端", "Pushed pending Git commits to the remote")
                self._append_log(self._tr(
                    f"推送 {self._protocol_label(protocol)} 提交",
                    f"Push commits to {self._protocol_label(protocol)}",
                ), "成功", tone="success", tooltip=summary)
                self._record_result("成功", summary, protocol=protocol, target=batch["target_display"])
                return summary
            summary = self._tr(f"{nb_prefix}{self._protocol_label(protocol)}已是最新状态", f"{nb_prefix}{self._protocol_label(protocol)} is up to date")
            if only_path is None:
                self._append_log(self._tr(
                    f"{self._protocol_label(protocol)}同步",
                    f"{self._protocol_label(protocol)} sync",
                ), "无变更", tone="info", tooltip=summary)
            self._record_result("无变更", summary, protocol=protocol, target=batch["target_display"])
            return summary

        summary = self._tr(
            f"{nb_prefix}推送 {total_pushed} 篇 · 拉取 {total_pulled} 篇 · 冲突 {total_conflicts} 篇",
            f"{nb_prefix}Pushed: {total_pushed} · Pulled: {total_pulled} · Conflicts: {total_conflicts}",
        )
        if total_assets > 0:
            summary += self._tr(f" · 附件 {total_assets} 个", f" · Attachments: {total_assets}")
        self._record_result(
            "成功",
            summary,
            protocol=protocol,
            target=batch["target_display"],
            pushed=total_pushed,
            pulled=total_pulled,
            conflicts=total_conflicts,
            assets=total_assets,
        )
        return self._tr(f"已完成{self._protocol_label(protocol)}同步：{summary}", f"{self._protocol_label(protocol)} sync complete: {summary}")

    # ---------- Dispatch & UI ----------

    def _build_pending_confirm(self, batch, reasons):
        sample_lines = []
        multi = len(batch["plans"]) > 1
        for plan in batch["plans"]:
            prefix = f"{plan['nb_label']}/" if multi else ""
            base_map = plan["base_map"]
            local_notes = plan["local_notes"]
            remote_notes = plan["remote_notes"]
            pull_ow_lines = [
                self._tr(f"[覆盖本地] {prefix}{p}", f"[Overwrite local] {prefix}{p}")
                if base_map.get(p) != sha256_text(local_notes[p])
                else self._tr(f"[更新本地] {prefix}{p}", f"[Update local] {prefix}{p}")
                for p in plan["to_pull_overwrite"]
            ]
            push_ow_lines = [
                self._tr(f"[覆盖远端] {prefix}{p}", f"[Overwrite remote] {prefix}{p}")
                if base_map.get(p) != sha256_text(remote_notes[p])
                else self._tr(f"[更新远端] {prefix}{p}", f"[Update remote] {prefix}{p}")
                for p in plan["to_push_overwrite"]
            ]
            sample_lines.extend(
                pull_ow_lines
                + push_ow_lines
                + [self._tr(f"[冲突副本] {prefix}{p} -> {cr}", f"[Conflict copy] {prefix}{p} -> {cr}") for p, cr, _ in plan["conflicts"]]
                + [self._tr(f"[拉取] {prefix}{p}", f"[Pull] {prefix}{p}") for p in plan["to_pull_new"]]
                + [self._tr(f"[推送] {prefix}{p}", f"[Push] {prefix}{p}") for p in plan["to_push_new"]]
                + [self._tr(f"[远端缺失] {prefix}{p}", f"[Missing remotely] {prefix}{p}") for p in plan["remote_missing"]]
                + [self._tr(f"[本地缺失] {prefix}{p}", f"[Missing locally] {prefix}{p}") for p in plan["local_missing"]]
            )
        return {
            "scope_key": self._result_key(),
            "fingerprint": batch["fingerprint"],
            "protocol": batch["protocol"],
            "target_display": batch["target_display"],
            "reasons": list(reasons),
            "badge": self._tr(f"需确认 · {len(reasons)} 项风险", f"Confirmation required · Risks: {len(reasons)}"),
            "sample_lines": sample_lines,
        }

    def _assess_batch_dangerous_changes(self, batch, cfg, saved_path=None):
        reasons = []
        multi = len(batch["plans"]) > 1
        for plan in batch["plans"]:
            nb_reasons = self._assess_dangerous_changes(plan, cfg, saved_path=saved_path)
            for r in nb_reasons:
                reasons.append(f"{plan['nb_label']}: {r}" if multi else r)
        return reasons

    def _run_sync(self, bridge, only_path=None, only_nb_root=None, confirmed=False, approved_batch=None, report_progress=False):
        self._refresh_known_notebooks(bridge)
        protocol = self.config.get("protocol", "local_mirror")
        target_error = self._target_error(self.config)
        if target_error:
            self.last_status = target_error
            return target_error

        if approved_batch is not None:
            batch = approved_batch
            protocol = batch.get("protocol", protocol)
        else:
            notebooks = self._selected_notebooks(self.config)
            if only_nb_root:
                norm_only = self._norm_nb_path(only_nb_root)
                if norm_only not in notebooks:
                    return ""
                notebooks = [norm_only]
            if not notebooks:
                msg = self._tr("请至少选择一个笔记本", "Select at least one notebook")
                self.last_status = msg
                return msg
            try:
                batch = self._compute_batch_plan(
                    bridge,
                    self.config,
                    notebooks,
                    only_path=only_path,
                    inspect_remote=True,
                    force_refresh=True,
                )
            except Exception as exc:
                msg = self._tr(
                    f"{self._protocol_label(protocol)}同步未完成: {self._error_detail(exc)}",
                    f"{self._protocol_label(protocol)} sync failed: {self._error_detail(exc)}",
                )
                self._append_log(self._tr(
                    f"{self._protocol_label(protocol)}同步",
                    f"{self._protocol_label(protocol)} sync",
                ), "失败", tone="danger", tooltip=msg)
                self._record_result("失败", msg, protocol=protocol)
                self._save_runtime(bridge)
                self.last_status = msg
                raise RuntimeError(msg) from exc

        if batch.get("remote_error"):
            msg = batch["remote_error"]
            self._append_log(self._tr(f"{self._protocol_label(protocol)}同步", f"{self._protocol_label(protocol)} sync"), "失败", tone="danger", tooltip=msg)
            self._record_result("失败", msg, protocol=protocol, target=batch["target_display"])
            self._save_runtime(bridge)
            self.last_status = msg
            raise RuntimeError(msg)

        if not confirmed:
            reasons = self._assess_batch_dangerous_changes(batch, self.config, saved_path=only_path)
            if reasons:
                if only_path is not None:
                    msg = self._tr(f"自动同步暂停（{reasons[0]}），请点击立即同步确认", f"Auto-sync paused ({reasons[0]}). Click Sync Now to confirm.")
                    self._append_log(self._tr(f"自动同步暂停 ({only_path})", f"Auto-sync paused ({only_path})"), "待确认", tone="warning", tooltip=msg)
                    self._record_result("待确认", msg, protocol=protocol, target=batch["target_display"])
                    self._save_runtime(bridge)
                    self.last_status = msg
                    return msg
                self.pending_confirm = self._build_pending_confirm(batch, reasons)
                msg = self._tr("检测到危险变更，请先确认后执行", "Risky changes detected. Confirm to continue.")
                self._append_log(reasons[0], "待确认", tone="warning", tooltip=msg)
                self._record_result("待确认", reasons[0], protocol=protocol, target=batch["target_display"])
                self._save_runtime(bridge)
                self.last_status = msg
                return msg

        try:
            msg = self._execute_batch_plan(bridge, batch, only_path=only_path, report_progress=report_progress)
        except Exception as exc:
            msg = self._error_detail(exc)
            if not msg.startswith(self._protocol_label(protocol)) and "Git" not in msg:
                msg = self._tr(f"{self._protocol_label(protocol)}同步未完成: {msg}", f"{self._protocol_label(protocol)} sync failed: {msg}")
            self._append_log(self._tr(f"{self._protocol_label(protocol)}同步", f"{self._protocol_label(protocol)} sync"), "失败", tone="danger", tooltip=msg)
            self._record_result("失败", msg, protocol=protocol, target=batch["target_display"])
            self._save_runtime(bridge)
            self.last_status = msg
            raise RuntimeError(msg) from exc

        self._save_runtime(bridge)
        self.last_status = msg
        return msg

    def _run_test_conn(self, cfg=None):
        c = cfg or self.config
        err = self._target_error(c, require_notebooks=False)
        if err:
            self.last_status = err
            return False, err
        prev_cfg = self.config
        self.config = c
        try:
            protocol = c.get("protocol", "local_mirror")
            if protocol == "webdav":
                ok, msg = self._test_webdav()
            elif protocol == "git":
                ok, msg = self._test_git()
            else:
                ok, msg = self._test_local_mirror()
        finally:
            self.config = prev_cfg
        self._append_log(
            self._tr(f"测试连接 ({self._protocol_label(protocol)})", f"Test connection ({self._protocol_label(protocol)})"),
            "通过" if ok else "未连通",
            tone="success" if ok else "danger",
            tooltip=msg,
        )
        self.last_status = msg
        return bool(ok), msg

    def _confirmation_card(self):
        pending = self.pending_confirm
        lines = [self._tr(f"[风险] {reason}", f"[Risk] {reason}") for reason in pending["reasons"]]
        samples = pending["sample_lines"]
        remaining = max(0, 9 - len(lines))
        lines.extend(samples[:remaining])
        if len(samples) > remaining:
            lines.append(self._tr(f"… 其余 {len(samples) - remaining} 项变更", f"… {len(samples) - remaining} more changes"))
        preview = {
            "variant": "plan",
            "palette": "warm",
            "title": self._protocol_label(pending["protocol"]),
            "body": "\n".join(lines),
        }
        if pending.get("badge"):
            preview["badge"] = pending["badge"]
        if pending.get("target_display"):
            preview["subtitle"] = pending["target_display"]
        return {
            "id": "preview-card",
            "title": self._tr("确认同步变更", "Review Sync Changes"),
            "items": [
                {
                    "kind": "preview",
                    "preview": preview,
                },
                {
                    "kind": "actions",
                    "buttons": [
                        {"id": "confirm_sync_card", "label": self._tr("确认同步", "Confirm Sync"), "variant": "danger"},
                        {"id": "cancel_confirm", "label": self._tr("取消", "Cancel"), "variant": "secondary"},
                    ],
                },
            ],
        }

    def _conflict_policy_item(self, c):
        return {
            "kind": "segmented",
            "id": "conflict_policy",
            "label": self._tr("双端冲突处理", "Conflict Resolution"),
            "value": c["conflict_policy"],
            "options": [
                {"value": "keep_both", "label": self._tr("生成冲突副本", "Keep Both Copies")},
                {"value": "local_first", "label": self._tr("优先本地", "Prefer Local")},
                {"value": "remote_first", "label": self._tr("优先远端", "Prefer Remote")},
            ],
        }

    def _build_legacy_page(self, c):
        protocol = c["protocol"]

        target_items = [
            {
                "kind": "segmented",
                "id": "protocol",
                "label": self._tr("同步方式", "Sync Method"),
                "value": protocol,
                "options": [
                    {"value": "local_mirror", "label": self._tr("目录镜像", "Local mirror")},
                    {"value": "webdav", "label": "WebDAV"},
                    {"value": "git", "label": self._tr("Git 仓库", "Git repository")},
                ],
            },
            {
                "kind": "folder",
                "id": "mirror_dir",
                "label": self._tr("同步文件夹", "Sync Folder"),
                "value": self._resolve_mirror_dir(c),
                "visible_when": {"control_id": "protocol", "equals": "local_mirror"},
            },
        ]
        for kind, key, label, placeholder in (
            ("input", "webdav_url", self._tr("服务器地址", "Server Address"), "https://dav.example.com"),
            ("input", "webdav_dir", self._tr("远端目录", "Remote Folder"), "/BlockNotes"),
            ("input", "webdav_user", self._tr("用户名", "Username"), ""),
            ("secret", "webdav_pass", self._tr("密码", "Password"), ""),
        ):
            target_items.append({
                "kind": kind, "id": key, "label": label, "value": c[key],
                "placeholder": placeholder,
                "visible_when": {"control_id": "protocol", "equals": "webdav"},
            })

        target_items.extend([
            {
                "kind": "input",
                "id": "git_remote",
                "label": self._tr("仓库地址", "Repository Address"),
                "value": c["git_remote"],
                "placeholder": "git@github.com:user/notes.git",
                "visible_when": {"control_id": "protocol", "equals": "git"},
            },
            {
                "kind": "input",
                "id": "git_branch",
                "label": self._tr("分支", "Branch"),
                "value": c["git_branch"],
                "placeholder": "main",
                "visible_when": {"control_id": "protocol", "equals": "git"},
            },
            {
                "kind": "segmented",
                "id": "git_auth",
                "label": self._tr("认证方式", "Authentication"),
                "value": c["git_auth"],
                "options": [
                    {"value": "ssh", "label": "SSH"},
                    {"value": "token", "label": self._tr("HTTPS 令牌", "HTTPS Token")},
                ],
                "visible_when": {"control_id": "protocol", "equals": "git"},
            },
        ])
        if protocol == "git":
            target_items.append({
                "kind": "secret",
                "id": "git_token",
                "label": self._tr("访问令牌", "Access Token"),
                "value": c["git_token"],
                "visible_when": {"control_id": "git_auth", "equals": "token"},
            })
        target_items.extend([
            self._conflict_policy_item(c),
            {
                "kind": "switch",
                "id": "auto_sync",
                "label": self._tr("保存笔记后自动同步", "Sync Automatically on Save"),
                "value": c["auto_sync"],
            },
            {
                "kind": "actions",
                "visible_when": {"control_id": "protocol", "in": ["webdav", "git"]},
                "buttons": [
                    {"id": "test_conn", "label": self._tr("测试连接", "Test Connection"), "variant": "secondary"},
                    {"id": "save_config", "label": self._tr("保存", "Save"), "variant": "primary"},
                ],
            },
        ])
        return [{"id": "target-card", "title": self._tr("同步设置", "Sync Settings"), "items": target_items}]

    def build_page(self, cfg=None):
        c = cfg or self.config
        protocol = c["protocol"]

        if self.supports_checklist and self.supports_form_layout:
            selected = self._selected_notebooks(c)
            nb_options = []
            for entry in self.known_notebooks:
                path = entry["path"]
                opt = {
                    "value": path,
                    "label": entry["name"],
                    "detail": self._display_path(path),
                    "tooltip": path,
                }
                if entry.get("active"):
                    opt["badge"] = self._tr("当前", "Current")
                nb_options.append(opt)

            nb_meta = self._tr(f"已选 {len(selected)} / {len(nb_options)}", f"Selected: {len(selected)} / {len(nb_options)}") if nb_options else ""
            notebooks_card = {
                "id": "notebooks-card",
                "title": self._tr("同步笔记本", "Notebooks to Sync"),
                "meta": nb_meta,
                "items": [
                    {
                        "kind": "checklist",
                        "id": "selected_notebooks",
                        "value": selected,
                        "options": nb_options,
                        "empty_text": self._tr("暂无已打开的笔记本", "No open notebooks"),
                    }
                ],
            }

            target_items = [
                {
                    "kind": "segmented",
                    "id": "protocol",
                    "layout": "full",
                    "value": protocol,
                    "options": [
                        {"value": "local_mirror", "label": self._tr("目录镜像", "Local mirror")},
                        {"value": "webdav", "label": "WebDAV"},
                        {"value": "git", "label": self._tr("Git 仓库", "Git repository")},
                    ],
                },
                {
                    "kind": "folder",
                    "id": "mirror_dir",
                    "label": self._tr("目标文件夹", "Destination Folder"),
                    "layout": "stacked",
                    "value": self._resolve_mirror_dir(c),
                    "visible_when": {"control_id": "protocol", "equals": "local_mirror"},
                },
                {
                    "kind": "input",
                    "id": "webdav_url",
                    "label": self._tr("服务器地址", "Server Address"),
                    "layout": "stacked",
                    "value": c["webdav_url"],
                    "placeholder": "https://dav.example.com",
                    "visible_when": {"control_id": "protocol", "equals": "webdav"},
                },
                {
                    "kind": "input",
                    "id": "webdav_dir",
                    "label": self._tr("远端目录", "Remote Folder"),
                    "layout": "stacked",
                    "value": c["webdav_dir"],
                    "placeholder": "/BlockNotes",
                    "visible_when": {"control_id": "protocol", "equals": "webdav"},
                },
                {
                    "kind": "group",
                    "visible_when": {"control_id": "protocol", "equals": "webdav"},
                    "fields": [
                        {
                            "kind": "input",
                            "id": "webdav_user",
                            "label": self._tr("用户名", "Username"),
                            "layout": "stacked",
                            "value": c["webdav_user"],
                            "placeholder": self._tr("账号", "Account"),
                        },
                        {
                            "kind": "secret",
                            "id": "webdav_pass",
                            "label": self._tr("密码", "Password"),
                            "layout": "stacked",
                            "value": c["webdav_pass"],
                            "placeholder": self._tr("应用密码或口令", "App password or passphrase"),
                        },
                    ],
                },
                {
                    "kind": "input",
                    "id": "git_remote",
                    "label": self._tr("仓库地址", "Repository Address"),
                    "layout": "stacked",
                    "value": c["git_remote"],
                    "placeholder": "git@github.com:user/notes.git",
                    "visible_when": {"control_id": "protocol", "equals": "git"},
                },
                {
                    "kind": "input",
                    "id": "git_branch",
                    "label": self._tr("分支", "Branch"),
                    "layout": "stacked",
                    "value": c["git_branch"],
                    "placeholder": "main",
                    "visible_when": {"control_id": "protocol", "equals": "git"},
                },
                {
                    "kind": "group",
                    "visible_when": {"control_id": "protocol", "equals": "git"},
                    "fields": [
                        {
                            "kind": "segmented",
                            "id": "git_auth",
                            "label": self._tr("认证方式", "Authentication"),
                            "layout": "stacked",
                            "value": c["git_auth"],
                            "options": [
                                {"value": "ssh", "label": "SSH"},
                                {"value": "token", "label": self._tr("HTTPS 令牌", "HTTPS Token")},
                            ],
                        },
                        {
                            "kind": "secret",
                            "id": "git_token",
                            "label": self._tr("访问令牌", "Access Token"),
                            "layout": "stacked",
                            "value": c["git_token"],
                            "placeholder": "ghp_...",
                            "visible_when": {"control_id": "git_auth", "equals": "token"},
                        },
                    ],
                },
                {
                    "kind": "actions",
                    "visible_when": {"control_id": "protocol", "in": ["webdav", "git"]},
                    "buttons": [
                        {"id": "test_conn", "label": self._tr("测试连接", "Test Connection"), "variant": "secondary"},
                        {"id": "save_config", "label": self._tr("保存", "Save"), "variant": "primary"},
                    ],
                },
            ]

            target_card = {
                "id": "target-card",
                "title": self._tr("同步目标", "Sync Destination"),
                "items": target_items,
            }
            options_card = {
                "id": "options-card",
                "title": self._tr("同步选项", "Sync Options"),
                "items": [
                    self._conflict_policy_item(c),
                    {
                        "kind": "switch",
                        "id": "auto_sync",
                        "label": self._tr("保存笔记后自动同步", "Sync Automatically on Save"),
                        "value": c["auto_sync"],
                    },
                ],
            }
            cards = [notebooks_card, target_card, options_card]
        else:
            cards = self._build_legacy_page(c)

        has_pending_confirm = bool(
            self.pending_confirm
            and self.pending_confirm.get("scope_key") == self._result_key()
            and c == self.config
        )
        if has_pending_confirm:
            cards.insert(0, self._confirmation_card())

        configured = not self._target_error(c)
        last_result = self._get_last_result() or {}
        last_ok = last_result.get("last_success")
        history_meta = (
            self._tr(f"上次成功 {last_ok['time']}", f"Last successful sync: {last_ok['time']}")
            if isinstance(last_ok, dict) and last_ok.get("time")
            else ""
        )
        history_entries = [
            self._log_for_page(entry)
            for entry in self.logs[:6]
            if isinstance(entry, dict)
        ]
        cards.append({
            "id": "history-card",
            "title": self._tr("最近同步记录", "Recent Sync Activity"),
            "meta": history_meta,
            "items": [
                {
                    "kind": "log_list",
                    "id": "sync_logs",
                    "empty_text": self._tr("暂无同步记录", "No sync activity yet"),
                    "entries": history_entries,
                }
            ],
        })

        status = self.last_status
        if not status and configured and c == self.config:
            if has_pending_confirm:
                status = self._tr("检测到危险变更，请确认后同步", "Risky changes detected. Confirm to sync.")
            elif isinstance(last_ok, dict) and last_ok.get("time"):
                sync_hm = format_hm(last_ok["time"])
                status = self._tr(f"上次同步 {sync_hm}", f"Last sync {sync_hm}")
            elif last_result.get("summary"):
                status = str(last_result["summary"])
                if self._is_en() and last_result.get("locale") != "en" and CHINESE_TEXT.search(status):
                    status = LOG_STATUS_EN.get(str(last_result.get("status")), "See recent sync activity for the last result")
        header_actions = []
        if has_pending_confirm:
            header_actions = [
                {"id": "confirm_sync", "label": self._tr("确认同步", "Confirm Sync"), "variant": "danger"},
            ]
        elif configured:
            header_actions = [
                {"id": "sync_now", "label": self._tr("立即同步", "Sync Now"), "variant": "primary"},
            ]
        return {
            "title": self._tr("同步", "Sync"),
            "status": status,
            "header_actions": header_actions,
            "cards": cards,
        }

    def handle(self, bridge, method, params):
        if method == "plugin.initialize":
            self.plugin_id = str(params.get("plugin_id") or "block-sync")
            self.data_dir = str(params.get("data_dir") or "")
            dl = str(params.get("downloads_dir") or "").strip()
            self.downloads_dir = dl or os.path.expanduser("~/Downloads")
            self.notebook_root = str(params.get("notebook_root") or "")
            self.locale = str(params.get("locale") or "zh")
            caps = set(params.get("ui_capabilities") or [])
            self.kv_tooltip = "kv_tooltip" in caps
            self.supports_checklist = "checklist" in caps
            self.supports_form_layout = "form_layout" in caps
            self.supports_multi_notebook = "multi_notebook" in caps
            self.supports_action_progress = "action_progress" in caps
            raw_nbs = params.get("notebooks")
            if isinstance(raw_nbs, list):
                self.known_notebooks = [str(p) for p in raw_nbs if str(p or "").strip()]
            self._load_state(bridge)
            return {"ready": True}

        if method == "plugin.render":
            self._refresh_known_notebooks(bridge)
            values = params.get("values")
            render_status = ""
            accepted = {}
            if isinstance(values, dict) and values:
                cfg = self._normalize_config(values, base=self.config)
                changed_immediate = False
                if "selected_notebooks" in values and cfg["selected_notebooks"] != self.config["selected_notebooks"]:
                    self.config["selected_notebooks"] = list(cfg["selected_notebooks"])
                    self._clear_pending_confirm(bridge)
                    self._remote_preview_cache.clear()
                    self.last_status = ""
                    changed_immediate = True
                if cfg["auto_sync"] != self.config["auto_sync"]:
                    self.config["auto_sync"] = cfg["auto_sync"]
                    changed_immediate = True
                if cfg["conflict_policy"] != self.config["conflict_policy"]:
                    self.config["conflict_policy"] = cfg["conflict_policy"]
                    self._clear_pending_confirm(bridge)
                    self._remote_preview_cache.clear()
                    self.last_status = ""
                    changed_immediate = True
                if cfg["protocol"] == "local_mirror":
                    mirror_err = self._target_error(cfg, require_notebooks=False)
                    if not mirror_err:
                        if self.config["protocol"] != "local_mirror" or self.config["mirror_dir"] != cfg["mirror_dir"]:
                            self.config["protocol"] = "local_mirror"
                            self.config["mirror_dir"] = cfg["mirror_dir"]
                            self._clear_pending_confirm(bridge)
                            self._remote_preview_cache.clear()
                            self.last_status = self._tr("已启用本地镜像目录", "Local mirror folder enabled")
                            changed_immediate = True
                    elif cfg["mirror_dir"]:
                        render_status = mirror_err
                if changed_immediate:
                    self._save_config(bridge)
                accepted = {
                    key: self.config[key]
                    for key in ("selected_notebooks", "auto_sync", "conflict_policy", "protocol", "mirror_dir")
                    if key in values and cfg[key] == self.config[key]
                }
            else:
                cfg = dict(self.config)
                cfg["selected_notebooks"] = list(self.config.get("selected_notebooks") or [])
            page = self.build_page(cfg=cfg)
            if render_status:
                page["status"] = render_status
            return {"page": page, "values": accepted}

        if method == "plugin.action":
            self._refresh_known_notebooks(bridge)
            values = params.get("values") or {}
            action_id = str(params.get("action_id") or "")
            ok = True
            tone = "info"
            if action_id == "save_config":
                next_cfg = self._normalize_config(values)
                status = self._target_error(next_cfg, require_notebooks=False)
                if status:
                    self.last_status = status
                    return {
                        "ok": False,
                        "tone": "danger",
                        "values": dict(next_cfg),
                        "page": self.build_page(cfg=next_cfg),
                        "status": status,
                    }
                if next_cfg != self.config:
                    self._clear_pending_confirm(bridge)
                    self._remote_preview_cache.clear()
                self.config = next_cfg
                self._save_config(bridge)
                status = self._tr("已保存同步目标配置", "Sync destination saved")
                self.last_status = status
                ok = True
                tone = "success"
            elif action_id == "test_conn":
                next_cfg = self._normalize_config(values)
                ok, status = self._run_test_conn(cfg=next_cfg)
                self._save_runtime(bridge)
                return {
                    "ok": ok,
                    "tone": "success" if ok else "danger",
                    "values": dict(next_cfg),
                    "page": self.build_page(cfg=next_cfg),
                    "status": status,
                }
            elif action_id == "sync_now":
                if isinstance(values, dict) and values:
                    next_cfg = self._normalize_config(values)
                    err = self._target_error(next_cfg)
                    if err:
                        self.last_status = err
                        return {
                            "ok": False,
                            "tone": "danger",
                            "values": dict(next_cfg),
                            "page": self.build_page(cfg=next_cfg),
                            "status": err,
                        }
                    if next_cfg != self.config:
                        self._clear_pending_confirm(bridge)
                        self._remote_preview_cache.clear()
                        self.config = next_cfg
                        self._save_config(bridge)
                err = self._target_error(self.config)
                if err or not self._selected_notebooks(self.config):
                    status = err or self._tr("请至少选择一个笔记本", "Select at least one notebook")
                    self.last_status = status
                    ok = False
                    tone = "danger"
                else:
                    self._clear_pending_confirm(bridge)
                    status = self._run_sync(bridge, report_progress=True)
                    if self.pending_confirm:
                        ok = True
                        tone = "warning"
                    else:
                        ok = True
                        tone = "success"
            elif action_id in ("confirm_sync", "confirm_sync_card"):
                pc = self.pending_confirm
                if not pc or pc.get("scope_key") != self._result_key():
                    err = self._target_error(self.config)
                    if err or not self._selected_notebooks(self.config):
                        status = err or self._tr("请至少选择一个笔记本", "Select at least one notebook")
                        self.last_status = status
                        ok = False
                        tone = "danger"
                    else:
                        self.pending_confirm = None
                        status = self._run_sync(bridge, report_progress=True)
                        ok = True
                        tone = "warning" if self.pending_confirm else "success"
                else:
                    protocol = self.config.get("protocol", "local_mirror")
                    notebooks = self._selected_notebooks(self.config)
                    try:
                        batch = self._compute_batch_plan(bridge, self.config, notebooks, inspect_remote=True, force_refresh=True)
                    except Exception as exc:
                        msg = self._tr(
                            f"{self._protocol_label(protocol)}同步未完成: {self._error_detail(exc)}",
                            f"{self._protocol_label(protocol)} sync failed: {self._error_detail(exc)}",
                        )
                        self._append_log(self._tr(
                            f"{self._protocol_label(protocol)}同步",
                            f"{self._protocol_label(protocol)} sync",
                        ), "失败", tone="danger", tooltip=msg)
                        self._record_result("失败", msg, protocol=protocol)
                        self._save_runtime(bridge)
                        self.last_status = msg
                        raise RuntimeError(msg) from exc

                    if batch.get("remote_error"):
                        msg = batch["remote_error"]
                        self._append_log(self._tr(
                            f"{self._protocol_label(batch['protocol'])}同步",
                            f"{self._protocol_label(batch['protocol'])} sync",
                        ), "失败", tone="danger", tooltip=msg)
                        self._record_result("失败", msg, protocol=batch["protocol"], target=batch["target_display"])
                        self._save_runtime(bridge)
                        self.last_status = msg
                        raise RuntimeError(msg)

                    if batch["fingerprint"] != pc.get("fingerprint"):
                        reasons = self._assess_batch_dangerous_changes(batch, self.config)
                        if reasons:
                            self.pending_confirm = self._build_pending_confirm(batch, reasons)
                            self._append_log(reasons[0], "待确认", tone="warning", tooltip=self._tr(
                                "同步计划已变化，请重新确认",
                                "The sync plan changed. Review and confirm it again.",
                            ))
                            self._record_result("待确认", self._tr(
                                "同步计划已变化，请重新确认",
                                "The sync plan changed. Review and confirm it again.",
                            ), protocol=batch["protocol"], target=batch["target_display"])
                            self._save_runtime(bridge)
                            status = self._tr("同步计划已变化，请重新确认", "The sync plan changed. Review and confirm it again.")
                            self.last_status = status
                            ok = False
                            tone = "warning"
                        else:
                            self.pending_confirm = None
                            self._append_log(self._tr("同步计划已变化", "The sync plan changed"), "待确认", tone="warning", tooltip=self._tr(
                                "原危险变更已消除，请重新同步",
                                "The original risks are gone. Start sync again.",
                            ))
                            self._record_result("待确认", self._tr(
                                "同步计划已变化，请重新同步",
                                "The sync plan changed. Start sync again.",
                            ), protocol=batch["protocol"], target=batch["target_display"])
                            self._save_runtime(bridge)
                            status = self._tr("同步计划已变化，请重新同步", "The sync plan changed. Start sync again.")
                            self.last_status = status
                            ok = False
                            tone = "warning"
                    else:
                        self._clear_pending_confirm(bridge)
                        err = self._target_error(self.config)
                        if err or not self._selected_notebooks(self.config):
                            status = err or self._tr("请至少选择一个笔记本", "Select at least one notebook")
                            self.last_status = status
                            ok = False
                            tone = "danger"
                        else:
                            status = self._run_sync(bridge, confirmed=True, approved_batch=batch, report_progress=True)
                            ok = True
                            tone = "success"
            elif action_id == "cancel_confirm":
                self.pending_confirm = None
                self._append_log(self._tr("危险变更同步", "Sync with risky changes"), "已取消", tone="info", tooltip=self._tr(
                    "用户已取消本次同步",
                    "The user canceled this sync",
                ))
                self._record_result("已取消", self._tr("用户已取消危险变更", "The user canceled the risky changes"))
                self._save_runtime(bridge)
                status = self._tr("已取消本次同步", "Sync canceled")
                self.last_status = status
                ok = True
                tone = "info"
            else:
                status = self._tr("已完成操作", "Action complete")
                self.last_status = status
                ok = True
                tone = "info"

            res = {
                "ok": ok,
                "tone": tone,
                "values": dict(self.config),
                "page": self.build_page(cfg=self.config),
                "status": status,
            }
            return res

        if method == "plugin.event":
            event_name = str(params.get("event") or "")
            rel_path = str(params.get("path") or "").replace("\\", "/")
            event_nb = self._norm_nb_path(params.get("notebook_root") or self.notebook_root)
            if (event_name == "note.saved" and self.config["auto_sync"]
                    and is_safe_rel_md(rel_path) and self._matches_scope(rel_path)
                    and not self._target_error(self.config)):
                self._refresh_known_notebooks(bridge)
                selected = self._selected_notebooks(self.config)
                if not self.supports_multi_notebook or (event_nb and event_nb in selected):
                    self._run_sync(bridge, only_path=rel_path, only_nb_root=event_nb or None)
            return {"handled": True}

        if method == "plugin.shutdown":
            return {"ok": True}

        raise RuntimeError(f"unsupported method: {method}")


def main():
    plugin = SyncPlugin()
    HostBridge().serve(plugin.handle, plugin._localize_error)


if __name__ == "__main__":
    main()
