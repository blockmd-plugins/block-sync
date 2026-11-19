#!/usr/bin/env python3
"""Official block-sync plugin for Block (blockmd)."""

import base64
from datetime import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


VALID_PROTOCOLS = ("local_mirror", "webdav", "git")
VALID_CONFLICT_POLICIES = ("keep_both", "remote_first", "local_first")
VALID_GIT_AUTHS = ("ssh", "token")
DELETE_GUARD_THRESHOLD = 5
MAX_LOG_ENTRIES = 20

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

    def serve(self, handler):
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
                    "error": {"code": -32000, "message": str(exc)},
                })


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode("utf-8"))


def now_hms():
    return datetime.now().strftime("%H:%M:%S")


def conflict_stamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def is_safe_rel_path(rel_path):
    if not rel_path or rel_path.startswith("/") or rel_path.startswith("\\"):
        return False
    norm = rel_path.replace("\\", "/")
    parts = norm.split("/")
    if any(part in ("", ".", "..") or part.startswith(".") for part in parts):
        return False
    return True


def is_safe_rel_md(rel_path):
    return is_safe_rel_path(rel_path) and rel_path.replace("\\", "/").endswith(".md")


def is_safe_rel_asset(rel_path):
    norm = rel_path.replace("\\", "/")
    return is_safe_rel_path(norm) and norm.startswith("assets/")


def make_conflict_path(rel_path, stamp):
    norm = rel_path.replace("\\", "/")
    if norm.endswith(".md"):
        return f"{norm[:-3]}.conflict-{stamp}.md"
    return f"{norm}.conflict-{stamp}.md"


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
            return "默认笔记本"
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

    def _notebook_subdir_map(self, notebooks, protocol, target_base):
        """Assign stable, collision-free subdirectories per notebook.

        Preserves legacy root layout when only one notebook is selected and it
        has not been synced under a subdirectory yet.
        """
        if not notebooks:
            return {}
        clean_names = {}
        name_counts = {}
        for nb in notebooks:
            base = os.path.basename(nb) or "notebook"
            safe = "".join(ch if ch not in ("/", "\\", "\x00") else "-" for ch in base).strip().strip(".") or "notebook"
            clean_names[nb] = safe
            name_counts[safe] = name_counts.get(safe, 0) + 1

        subdirs = {}
        for nb in notebooks:
            safe = clean_names[nb]
            if name_counts[safe] > 1:
                subdirs[nb] = f"{safe}-{sha256_text(nb)[:4]}"
            else:
                subdirs[nb] = safe

        if len(notebooks) == 1:
            nb = notebooks[0]
            sub = subdirs[nb]
            sub_meta = self._meta_key(protocol, f"{target_base}::{sub}", nb_key=nb)
            if sub_meta in self.sync_meta:
                return {nb: sub}
            return {nb: ""}

        return subdirs

    def _meta_key(self, protocol, target_id, nb_key=None):
        nb = nb_key or self._notebook_key()
        return f"nb:{nb}|{protocol}:{target_id}"

    def _get_base_map(self, meta_key, legacy_key=None):
        if meta_key in self.sync_meta and isinstance(self.sync_meta[meta_key], dict):
            return dict(self.sync_meta[meta_key])
        if legacy_key and legacy_key in self.sync_meta and isinstance(self.sync_meta[legacy_key], dict):
            return dict(self.sync_meta[legacy_key])
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

        self.pending_confirm = None
        self._remote_preview_cache = {}
        self.last_status = ""

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
            return self._webdav_base_url(c) or "未配置 WebDAV 地址"
        target = str(c.get("git_remote") or "").strip()
        branch = self._git_branch(c)
        repo_dir = self._resolve_local_git_dir(c)
        return f"{target} ({branch})" if target else f"{repo_dir} ({branch})"

    def _append_log(self, title, status, tone="", tooltip=""):
        entry = self._normalize_log({
            "title": str(title or "同步任务").strip() or "同步任务",
            "status": str(status or "成功").strip() or "成功",
            "time": now_hms(),
            "tone": tone,
            "tooltip": tooltip,
        })
        self.logs.insert(0, entry)
        self.logs = self.logs[:MAX_LOG_ENTRIES]

    def _protocol_label(self, protocol):
        return {
            "local_mirror": "目录镜像",
            "webdav": "WebDAV",
            "git": "Git 仓库",
        }.get(protocol, "目录镜像")

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
            return "请至少选择一个笔记本"
        protocol = cfg["protocol"]
        if protocol == "webdav":
            if not self._webdav_base_url(cfg):
                return "请填写有效的 WebDAV 地址"
        elif protocol == "git":
            if not str(cfg.get("git_remote") or "").strip():
                return "请填写 Git 仓库地址"
        elif protocol == "local_mirror":
            target = self._resolve_mirror_dir(cfg)
            if not target:
                return "请先选择同步文件夹"
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
                    return f"同步文件夹不能与笔记本「{self._notebook_label(nb)}」重叠"
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
            if is_safe_rel_md(rel_path):
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

    def _write_local_note(self, bridge, rel_path, content, nb_root=None):
        params = {"path": rel_path, "content": content}
        if nb_root and self.supports_multi_notebook:
            params["notebook_root"] = nb_root
        bridge.call_host("host.notes.write", params)

    def _read_local_assets(self, nb_root=None):
        assets = {}
        root_dir = nb_root or self.notebook_root
        if not root_dir:
            return assets
        root_real = os.path.realpath(root_dir)
        assets_dir = os.path.join(root_real, "assets")
        if not os.path.isdir(assets_dir):
            return assets
        for root, dirs, files in os.walk(assets_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for name in files:
                if name.startswith("."):
                    continue
                full = os.path.join(root, name)
                real_full = os.path.realpath(full)
                if not real_full.startswith(root_real + os.sep):
                    continue
                rel = os.path.relpath(real_full, root_real).replace(os.sep, "/")
                if not is_safe_rel_asset(rel):
                    continue
                with open(real_full, "rb") as fh:
                    assets[rel] = fh.read()
        return assets

    def _write_local_asset(self, rel_asset_path, data, nb_root=None):
        root_dir = nb_root or self.notebook_root
        if not root_dir or not is_safe_rel_asset(rel_asset_path):
            return False
        root_real = os.path.realpath(root_dir)
        dest = os.path.normpath(os.path.join(root_real, *rel_asset_path.split("/")))
        if not dest.startswith(root_real + os.sep):
            return False
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(data)
        return True

    def _check_delete_guard(self, base_map, local_notes, remote_notes, only_path=None):
        if only_path is not None or not self.config.get("delete_guard", True):
            return None
        remote_missing = [
            p for p in base_map
            if is_safe_rel_md(p) and p in local_notes and p not in remote_notes
        ]
        if len(remote_missing) > DELETE_GUARD_THRESHOLD:
            return (
                f"已触发删除保护：远端缺失 {len(remote_missing)} 篇已同步笔记"
                f"（超过 {DELETE_GUARD_THRESHOLD} 篇），已暂停同步"
            )
        local_missing = [
            p for p in base_map
            if is_safe_rel_md(p) and p in remote_notes and p not in local_notes
        ]
        if len(local_missing) > DELETE_GUARD_THRESHOLD:
            return (
                f"已触发删除保护：本地缺失 {len(local_missing)} 篇已同步笔记"
                f"（超过 {DELETE_GUARD_THRESHOLD} 篇），已暂停同步"
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

    def _sync_local_dir_assets(self, remote_dir, nb_root=None):
        root_dir = nb_root or self.notebook_root
        if not self.config.get("sync_assets", True) or not root_dir:
            return 0
        local_assets = self._read_local_assets(nb_root=root_dir)
        remote_assets = {}
        assets_dir = os.path.join(remote_dir, "assets")
        if os.path.isdir(assets_dir):
            for root, dirs, files in os.walk(assets_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for name in files:
                    if name.startswith("."):
                        continue
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, remote_dir).replace(os.sep, "/")
                    if is_safe_rel_asset(rel):
                        with open(full, "rb") as fh:
                            remote_assets[rel] = fh.read()

        policy = self.config.get("conflict_policy", "keep_both")
        synced = 0
        for rel in sorted(set(local_assets.keys()) | set(remote_assets.keys())):
            in_local = rel in local_assets
            in_remote = rel in remote_assets
            if in_local and not in_remote:
                self._write_mirror_bytes(remote_dir, rel, local_assets[rel])
                synced += 1
            elif in_remote and not in_local:
                if self._write_local_asset(rel, remote_assets[rel], nb_root=root_dir):
                    synced += 1
            elif sha256_bytes(local_assets[rel]) != sha256_bytes(remote_assets[rel]):
                if policy == "remote_first":
                    if self._write_local_asset(rel, remote_assets[rel], nb_root=root_dir):
                        synced += 1
                else:
                    self._write_mirror_bytes(remote_dir, rel, local_assets[rel])
                    synced += 1
        return synced

    # ---------- Local Mirror Mode ----------

    def _test_local_mirror(self):
        mirror_dir = self._resolve_mirror_dir()
        try:
            os.makedirs(mirror_dir, exist_ok=True)
            probe_file = os.path.join(mirror_dir, ".block-sync-probe")
            with open(probe_file, "w", encoding="utf-8") as fh:
                fh.write("ok")
            os.remove(probe_file)
            return True, f"目录镜像可用: {mirror_dir}"
        except Exception as exc:
            return False, f"目录镜像不可写: {sanitize_error_text(exc)}"

    def _scan_mirror_files(self, mirror_dir, only_path=None, scope=None):
        remote_files = {}
        if not os.path.isdir(mirror_dir):
            return remote_files
        if only_path:
            candidate = os.path.join(mirror_dir, *only_path.split("/"))
            if os.path.isfile(candidate):
                with open(candidate, "r", encoding="utf-8", errors="replace") as fh:
                    remote_files[only_path] = fh.read()
            return remote_files

        for root, dirs, files in os.walk(mirror_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for name in files:
                if name.startswith(".") or not name.endswith(".md"):
                    continue
                full = os.path.join(root, name)
                rel = os.path.relpath(full, mirror_dir).replace(os.sep, "/")
                if not is_safe_rel_md(rel) or not self._matches_scope(rel, scope):
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    remote_files[rel] = fh.read()
        return remote_files

    def _write_mirror_file(self, mirror_dir, rel_path, content):
        dest = os.path.join(mirror_dir, *rel_path.split("/"))
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(content)

    def _write_mirror_bytes(self, mirror_dir, rel_path, data):
        dest = os.path.join(mirror_dir, *rel_path.split("/"))
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(data)

    def _sync_local_mirror(self, bridge, only_path=None):
        mirror_dir = self._resolve_mirror_dir()
        os.makedirs(mirror_dir, exist_ok=True)

        local_notes = self._read_local_notes(bridge, only_path=only_path)
        remote_notes = self._scan_mirror_files(mirror_dir, only_path=only_path)

        meta_key = f"local_mirror:{mirror_dir}"
        base_map = dict(self.sync_meta.get(meta_key) or {})

        guard_msg = self._check_delete_guard(base_map, local_notes, remote_notes, only_path=only_path)
        if guard_msg:
            self._append_log("删除保护暂停", "待确认", tone="warning", tooltip=guard_msg)
            return guard_msg

        synced_count = 0
        all_paths = sorted(set(local_notes.keys()) | set(remote_notes.keys()))
        for rel_path in all_paths:
            in_local = rel_path in local_notes
            in_remote = rel_path in remote_notes
            if in_local and not in_remote:
                text = local_notes[rel_path]
                self._write_mirror_file(mirror_dir, rel_path, text)
                base_map[rel_path] = sha256_text(text)
                synced_count += 1
                self._append_log(f"推送 {rel_path}", "成功", tone="success", tooltip="已镜像到本地目录")
            elif in_remote and not in_local:
                text = remote_notes[rel_path]
                bridge.call_host("host.notes.write", {"path": rel_path, "content": text})
                base_map[rel_path] = sha256_text(text)
                synced_count += 1
                self._append_log(f"拉取 {rel_path}", "成功", tone="success", tooltip="已从镜像恢复")
            else:
                action, chosen_text, conflict_extra, new_hash = self._resolve_conflict_pair(
                    rel_path, local_notes[rel_path], remote_notes[rel_path], base_map.get(rel_path)
                )
                if action == "skip":
                    base_map[rel_path] = new_hash
                elif action == "push":
                    self._write_mirror_file(mirror_dir, rel_path, chosen_text)
                    base_map[rel_path] = new_hash
                    synced_count += 1
                    self._append_log(f"本地覆盖 {rel_path}", "成功", tone="success", tooltip="本地优先覆盖镜像")
                elif action == "pull":
                    bridge.call_host("host.notes.write", {"path": rel_path, "content": chosen_text})
                    base_map[rel_path] = new_hash
                    synced_count += 1
                    self._append_log(f"远端覆盖 {rel_path}", "成功", tone="success", tooltip="镜像优先更新本地")
                elif action == "keep_both":
                    conflict_rel, conflict_text = conflict_extra
                    bridge.call_host("host.notes.write", {"path": conflict_rel, "content": conflict_text})
                    self._write_mirror_file(mirror_dir, conflict_rel, conflict_text)
                    self._write_mirror_file(mirror_dir, rel_path, chosen_text)
                    base_map[rel_path] = new_hash
                    base_map[conflict_rel] = sha256_text(conflict_text)
                    synced_count += 1
                    self._append_log(f"冲突保留 {rel_path}", "冲突副本", tone="warning", tooltip=f"已保留副本 {conflict_rel}")

        asset_count = self._sync_local_dir_assets(mirror_dir)
        if asset_count > 0:
            self._append_log(f"同步 {asset_count} 个附件", "成功", tone="success")

        self.sync_meta[meta_key] = base_map
        self.stats["total_synced"] += synced_count
        self.stats["last_sync"] = now_hms()
        if synced_count == 0 and asset_count == 0 and not all_paths:
            return "当前笔记本暂无笔记"
        if synced_count == 0 and asset_count == 0:
            return "目录镜像已是最新，无需更新"
        if asset_count > 0:
            return f"已完成目录镜像同步，处理 {synced_count} 篇笔记、{asset_count} 个附件"
        return f"已完成目录镜像同步，处理 {synced_count} 篇笔记"

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

    def _webdav_ensure_dir(self, root_url, dir_rel):
        parts = [p for p in dir_rel.strip("/").split("/") if p and p not in (".", "..")]
        cur = root_url
        for part in parts:
            cur = cur + urllib.parse.quote(part) + "/"
            try:
                self._webdav_request("MKCOL", cur)
            except urllib.error.HTTPError as exc:
                if exc.code not in (405, 301, 302, 409):
                    raise

    def _test_webdav(self):
        root_url = self._webdav_root_url()
        base_url = self._webdav_base_url()
        if not root_url or not base_url:
            return False, "请填写有效的 WebDAV http(s) 地址"
        try:
            status, _ = self._webdav_request("PROPFIND", base_url, extra_headers={"Depth": "0"})
            if status in (200, 204, 207):
                return True, f"WebDAV 连接正常 (HTTP {status})"
            return False, f"WebDAV 响应异常 (HTTP {status})"
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and base_url != root_url:
                try:
                    status, _ = self._webdav_request("PROPFIND", root_url, extra_headers={"Depth": "0"})
                    if status in (200, 204, 207):
                        return True, "WebDAV 连通正常（远端目录将在同步时创建）"
                except Exception:
                    pass
            if exc.code in (401, 403):
                return False, f"WebDAV 认证失败 (HTTP {exc.code})"
            return False, f"WebDAV 请求失败 (HTTP {exc.code})"
        except Exception as exc:
            return False, f"WebDAV 连接不可达: {sanitize_error_text(exc)}"

    def _webdav_list_files(self, base_url, filter_fn, cfg=None, timeout=6):
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
                if not rel:
                    continue
                if is_col or href_text.endswith("/"):
                    rel_dir = rel.strip("/")
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

    def _webdav_ensure_parents(self, base_url, rel_path):
        parts = rel_path.split("/")[:-1]
        cur = base_url
        for part in parts:
            cur = cur + urllib.parse.quote(part) + "/"
            try:
                self._webdav_request("MKCOL", cur)
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

    def _webdav_put_text(self, base_url, rel_path, content):
        self._webdav_ensure_parents(base_url, rel_path)
        file_url = base_url + "/".join(urllib.parse.quote(p) for p in rel_path.split("/"))
        self._webdav_request(
            "PUT",
            file_url,
            body=content.encode("utf-8"),
            extra_headers={"Content-Type": "text/markdown; charset=utf-8"},
        )

    def _webdav_put_bytes(self, base_url, rel_path, data):
        self._webdav_ensure_parents(base_url, rel_path)
        file_url = base_url + "/".join(urllib.parse.quote(p) for p in rel_path.split("/"))
        self._webdav_request(
            "PUT",
            file_url,
            body=data,
            extra_headers={"Content-Type": "application/octet-stream"},
        )

    def _sync_webdav_assets(self, base_url, nb_root=None):
        root_dir = nb_root or self.notebook_root
        if not self.config.get("sync_assets", True) or not root_dir:
            return 0
        local_assets = self._read_local_assets(nb_root=root_dir)
        assets_url = base_url + "assets/"
        remote_asset_names = self._webdav_list_files(assets_url, lambda p: is_safe_rel_path(p) and not p.endswith("/"))
        remote_assets = {}
        for name in remote_asset_names:
            rel = f"assets/{name}"
            if not is_safe_rel_asset(rel):
                continue
            file_url = assets_url + "/".join(urllib.parse.quote(p) for p in name.split("/"))
            found, data = self._webdav_get_bytes(file_url)
            if found:
                remote_assets[rel] = data

        policy = self.config.get("conflict_policy", "keep_both")
        synced = 0
        for rel in sorted(set(local_assets.keys()) | set(remote_assets.keys())):
            in_local = rel in local_assets
            in_remote = rel in remote_assets
            if in_local and not in_remote:
                self._webdav_put_bytes(base_url, rel, local_assets[rel])
                synced += 1
            elif in_remote and not in_local:
                if self._write_local_asset(rel, remote_assets[rel], nb_root=root_dir):
                    synced += 1
            elif sha256_bytes(local_assets[rel]) != sha256_bytes(remote_assets[rel]):
                if policy == "remote_first":
                    if self._write_local_asset(rel, remote_assets[rel], nb_root=root_dir):
                        synced += 1
                else:
                    self._webdav_put_bytes(base_url, rel, local_assets[rel])
                    synced += 1
        return synced

    def _sync_webdav(self, bridge, only_path=None):
        root_url = self._webdav_root_url()
        base_url = self._webdav_base_url()
        if not root_url or not base_url:
            msg = "请先填写有效的 WebDAV http(s) 地址"
            self._append_log("WebDAV 同步", "失败", tone="danger", tooltip=msg)
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
                self._append_log("删除保护暂停", "待确认", tone="warning", tooltip=guard_msg)
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
                    self._append_log(f"推送 {rel_path}", "成功", tone="success", tooltip="已上传到 WebDAV")
                elif in_remote and not in_local:
                    text = remote_notes[rel_path]
                    bridge.call_host("host.notes.write", {"path": rel_path, "content": text})
                    base_map[rel_path] = sha256_text(text)
                    synced_count += 1
                    self._append_log(f"拉取 {rel_path}", "成功", tone="success", tooltip="已从 WebDAV 下载")
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
                        self._append_log(f"本地覆盖 {rel_path}", "成功", tone="success", tooltip="本地优先上传 WebDAV")
                    elif action == "pull":
                        bridge.call_host("host.notes.write", {"path": rel_path, "content": chosen_text})
                        base_map[rel_path] = new_hash
                        synced_count += 1
                        self._append_log(f"远端覆盖 {rel_path}", "成功", tone="success", tooltip="远端优先更新本地")
                    elif action == "keep_both":
                        conflict_rel, conflict_text = conflict_extra
                        bridge.call_host("host.notes.write", {"path": conflict_rel, "content": conflict_text})
                        self._webdav_put_text(base_url, conflict_rel, conflict_text)
                        self._webdav_put_text(base_url, rel_path, chosen_text)
                        base_map[rel_path] = new_hash
                        base_map[conflict_rel] = sha256_text(conflict_text)
                        synced_count += 1
                        self._append_log(f"冲突保留 {rel_path}", "冲突副本", tone="warning", tooltip=f"WebDAV 冲突已保留副本 {conflict_rel}")

            asset_count = 0 if only_path else self._sync_webdav_assets(base_url)
            if asset_count > 0:
                self._append_log(f"同步 {asset_count} 个附件", "成功", tone="success")

            self.sync_meta[meta_key] = base_map
            self.stats["total_synced"] += synced_count
            self.stats["last_sync"] = now_hms()
            if synced_count == 0 and asset_count == 0:
                return "WebDAV 已是最新状态"
            if asset_count > 0:
                return f"已完成 WebDAV 同步，处理 {synced_count} 篇笔记、{asset_count} 个附件"
            return f"已完成 WebDAV 同步，处理 {synced_count} 篇笔记"
        except Exception as exc:
            msg = f"WebDAV 同步未完成: {sanitize_error_text(exc)}"
            self._append_log("WebDAV 同步", "失败", tone="danger", tooltip=msg)
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

    def _resolve_local_git_dir(self, cfg=None):
        c = cfg or self.config
        target = str(c.get("git_remote") or "").strip()
        if target and not self._is_remote_git_url(target):
            expanded = os.path.expanduser(target)
            if os.path.isabs(expanded):
                return os.path.normpath(expanded)
            base = self.data_dir or os.getcwd()
            return os.path.normpath(os.path.join(base, expanded))
        selected = self._selected_notebooks(c)
        base_repos = os.path.join(self.data_dir or os.getcwd(), "git-repos")
        if len(selected) == 1:
            legacy = os.path.join(base_repos, self._notebook_slug(selected[0]))
            if os.path.isdir(os.path.join(legacy, ".git")):
                return legacy
        if target:
            return os.path.join(base_repos, f"repo-{sha256_text(target)[:12]}")
        return os.path.join(base_repos, self._notebook_slug())

    def _test_git(self):
        if not shutil.which("git"):
            return False, "当前环境未安装 git 命令"
        target = self.config.get("git_remote", "").strip()
        branch = self._git_branch()
        try:
            if target and self._is_remote_git_url(target):
                proc = self._run_git(["ls-remote", "--heads", target, branch])
                if proc.returncode == 0:
                    return True, f"Git 远端仓库连接正常（分支 {branch}）"
                err = sanitize_error_text(proc.stderr or proc.stdout or "连接失败")
                return False, f"Git 远端不可达: {err}"

            repo_dir = self._resolve_local_git_dir()
            if not os.path.isdir(repo_dir):
                return False, f"本地 Git 仓库目录不存在: {repo_dir}"
            proc = self._run_git(["rev-parse", "--is-inside-work-tree"], cwd=repo_dir)
            if proc.returncode != 0 or proc.stdout.strip() != "true":
                return False, f"目录不是有效的 Git 仓库: {repo_dir}"
            remote_proc = self._run_git(["remote"], cwd=repo_dir)
            remotes = [r.strip() for r in remote_proc.stdout.splitlines() if r.strip()]
            if remotes:
                ls_proc = self._run_git(["ls-remote", "--heads", remotes[0], branch], cwd=repo_dir)
                if ls_proc.returncode == 0:
                    return True, f"Git 仓库及远端 {remotes[0]} 正常"
                return True, f"本地 Git 仓库可用（远端 {remotes[0]} 当前离线）"
            return True, f"本地 Git 仓库可用: {repo_dir}"
        except Exception as exc:
            return False, f"Git 检测异常: {sanitize_error_text(exc)}"

    def _prepare_git_repo(self, cfg, allow_init_or_clone=True, allow_pull=True):
        if not shutil.which("git"):
            return False, "当前环境未安装 git 命令"
        target = str(cfg.get("git_remote") or "").strip()
        branch = self._git_branch(cfg)
        repo_dir = self._resolve_local_git_dir(cfg)

        if target and self._is_remote_git_url(target):
            if not os.path.isdir(os.path.join(repo_dir, ".git")):
                if not allow_init_or_clone:
                    return False, None
                os.makedirs(os.path.dirname(repo_dir), exist_ok=True)
                clone_proc = self._run_git(["clone", "--branch", branch, target, repo_dir], timeout=12, cfg=cfg)
                if clone_proc.returncode != 0:
                    clone_proc = self._run_git(["clone", target, repo_dir], timeout=12, cfg=cfg)
                if clone_proc.returncode != 0:
                    err = sanitize_error_text(clone_proc.stderr or clone_proc.stdout or "clone 失败")
                    return False, f"Git 远端不可达: {err}"
            else:
                url_proc = self._run_git(["remote", "get-url", "origin"], cwd=repo_dir, cfg=cfg)
                if url_proc.returncode == 0 and url_proc.stdout.strip() != target:
                    self._run_git(["remote", "set-url", "origin", target], cwd=repo_dir, cfg=cfg)
                if allow_pull:
                    pull_proc = self._run_git(["pull", "--rebase", "--autostash", "origin", branch], cwd=repo_dir, timeout=10, cfg=cfg)
                    if pull_proc.returncode != 0:
                        err_lower = (pull_proc.stderr or pull_proc.stdout or "").lower()
                        self._run_git(["rebase", "--abort"], cwd=repo_dir, cfg=cfg)
                        if (
                            "couldn't find remote ref" not in err_lower
                            and "does not have any commits" not in err_lower
                            and "no such ref" not in err_lower
                        ):
                            err = sanitize_error_text(pull_proc.stderr or pull_proc.stdout or "pull 失败")
                            return False, f"Git 拉取失败: {err}"
        else:
            if not os.path.isdir(os.path.join(repo_dir, ".git")):
                if not allow_init_or_clone:
                    return False, None
                os.makedirs(repo_dir, exist_ok=True)
                init_proc = self._run_git(["init", "-b", branch], cwd=repo_dir, cfg=cfg)
                if init_proc.returncode != 0:
                    init_proc = self._run_git(["init"], cwd=repo_dir, cfg=cfg)
                if init_proc.returncode != 0:
                    return False, "Git 仓库初始化失败"

        return True, repo_dir

    def _fetch_webdav_notes(self, cfg, only_path=None, scope="all", timeout=6, force_refresh=False, subdir=""):
        root_url = self._webdav_root_url(cfg)
        base_url = self._webdav_base_url(cfg, subdir=subdir)
        if not root_url or not base_url:
            return False, {}, "请先填写有效的 WebDAV http(s) 地址"

        cache_key = (base_url, scope, only_path or "")
        if not force_refresh and only_path is None and cache_key in self._remote_preview_cache:
            cached_ts, cached_notes = self._remote_preview_cache[cache_key]
            if time.time() - cached_ts < 15.0:
                return True, dict(cached_notes), None

        try:
            remote_paths = (
                [only_path]
                if only_path
                else [
                    p for p in self._webdav_list_files(base_url, is_safe_rel_md, cfg=cfg, timeout=timeout)
                    if self._matches_scope(p, scope)
                ]
            )
            remote_notes = {}
            for rel_path in remote_paths:
                if not is_safe_rel_md(rel_path):
                    continue
                file_url = base_url + "/".join(urllib.parse.quote(p) for p in rel_path.split("/"))
                found, raw_bytes = self._webdav_get_bytes(file_url, cfg=cfg, timeout=timeout)
                if found:
                    remote_notes[rel_path] = raw_bytes.decode("utf-8", errors="replace")
            if only_path is None:
                self._remote_preview_cache[cache_key] = (time.time(), dict(remote_notes))
            return True, remote_notes, None
        except Exception as exc:
            return False, {}, f"WebDAV 连接不可达: {sanitize_error_text(exc)}"

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
    ):
        nb_key = self._notebook_key(nb_root)
        nb_label = self._notebook_label(nb_root)
        protocol = cfg.get("protocol", "local_mirror")
        scope = cfg.get("sync_scope", "all")
        policy = cfg.get("conflict_policy", "keep_both")
        local_notes = self._read_local_notes(bridge, only_path=only_path, scope=scope, nb_root=nb_root)
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
            remote_notes = self._scan_mirror_files(target_dir, only_path=only_path, scope=scope)
        elif protocol == "webdav":
            root_base_url = self._webdav_base_url(cfg)
            base_url = self._webdav_base_url(cfg, subdir=subdir)
            meta_target = f"{root_base_url}::{subdir}" if (root_base_url and subdir) else (root_base_url or "unconfigured")
            meta_key = self._meta_key("webdav", meta_target, nb_key=nb_key)
            legacy_key = f"webdav:{root_base_url}" if (root_base_url and not subdir) else None
            if not base_url:
                remote_inspected = False
                remote_error = "请先填写有效的 WebDAV http(s) 地址"
            elif inspect_remote or force_refresh:
                ok, fetched, err = self._fetch_webdav_notes(
                    cfg,
                    only_path=only_path,
                    scope=scope,
                    timeout=6 if inspect_remote else 4,
                    force_refresh=force_refresh,
                    subdir=subdir,
                )
                if ok:
                    remote_notes = fetched
                else:
                    remote_inspected = False
                    remote_error = err
            else:
                cache_key = (base_url, scope, only_path or "")
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
                remote_notes = self._scan_mirror_files(target_dir, only_path=only_path, scope=scope)
            elif inspect_remote:
                ok, res = self._prepare_git_repo(cfg, allow_init_or_clone=True, allow_pull=True)
                if ok:
                    repo_root = res
                    target_dir = os.path.join(res, subdir) if subdir else res
                    remote_notes = self._scan_mirror_files(target_dir, only_path=only_path, scope=scope)
                else:
                    remote_inspected = False
                    remote_error = res
            elif os.path.isdir(os.path.join(repo_dir, ".git")):
                remote_notes = self._scan_mirror_files(target_dir, only_path=only_path, scope=scope)
            else:
                remote_inspected = False

        base_map = self._get_base_map(meta_key, legacy_key=legacy_key)
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
        n_pull_new = len(plan["to_pull_new"])
        n_pull_ow = len(plan["to_pull_overwrite"])
        overwrites = plan["to_push_overwrite"]
        n_push_ow = sum(
            path != saved_path or plan["base_map"].get(path) != sha256_text(plan["remote_notes"][path])
            for path in overwrites
        )
        n_conf = len(plan["conflicts"])
        n_rm_miss = len(plan["remote_missing"])
        n_loc_miss = len(plan["local_missing"])

        if plan["is_first_sync"] and (n_pull_new > 0 or n_pull_ow > 0 or n_push_ow > 0 or n_conf > 0):
            reasons.append(
                f"首次同步且远端已有内容（拉取 {n_pull_new} · 覆盖本地 {n_pull_ow} · 覆盖远端 {n_push_ow} · 冲突 {n_conf}）"
            )
        if n_pull_ow > 0:
            reasons.append(f"远端内容将覆盖本地 {n_pull_ow} 篇笔记")
        if n_push_ow > 0:
            reasons.append(f"本地内容将覆盖远端 {n_push_ow} 篇笔记")
        if n_conf > 0:
            reasons.append(f"存在 {n_conf} 篇双向冲突（将生成 .conflict 副本）")
        if cfg.get("delete_guard", True) and (n_rm_miss > DELETE_GUARD_THRESHOLD or n_loc_miss > DELETE_GUARD_THRESHOLD):
            reasons.append(
                f"触发批量缺失保护（远端缺失 {n_rm_miss} 篇 / 本地缺失 {n_loc_miss} 篇，阈值 {DELETE_GUARD_THRESHOLD}）"
            )
        elif n_pull_new + n_pull_ow > DELETE_GUARD_THRESHOLD:
            reasons.append(f"将向本地批量写入 {n_pull_new + n_pull_ow} 篇笔记（超 {DELETE_GUARD_THRESHOLD} 篇）")
        return reasons

    def _commit_and_push_git(self, repo_root, cfg):
        branch = self._git_branch(cfg)
        status_proc = self._run_git(["status", "--porcelain"], cwd=repo_root, cfg=cfg)
        if status_proc.returncode != 0:
            err = sanitize_error_text(status_proc.stderr or status_proc.stdout or "git status 失败")
            raise RuntimeError(f"Git 状态检查失败: {err}")

        if status_proc.stdout.strip():
            add_proc = self._run_git(["add", "-A"], cwd=repo_root, cfg=cfg)
            if add_proc.returncode != 0:
                err = sanitize_error_text(add_proc.stderr or add_proc.stdout or "git add 失败")
                raise RuntimeError(f"Git 暂存失败: {err}")

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
                err = sanitize_error_text(commit_proc.stderr or commit_proc.stdout or "git commit 失败")
                raise RuntimeError(f"Git 提交失败: {err}")

        remote_proc = self._run_git(["remote"], cwd=repo_root, cfg=cfg)
        if remote_proc.returncode != 0:
            err = sanitize_error_text(remote_proc.stderr or remote_proc.stdout or "git remote 失败")
            raise RuntimeError(f"Git 远端检查失败: {err}")

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
                    push_proc = self._run_git(
                        ["push", "-u", remote_name, f"HEAD:{branch}"],
                        cwd=repo_root,
                        timeout=12,
                        cfg=cfg,
                    )
                    if push_proc.returncode != 0:
                        err = sanitize_error_text(push_proc.stderr or push_proc.stdout or "push 失败")
                        raise RuntimeError(f"已提交到本地 Git，但远端推送未完成: {err}")
                    return True
        return False

    def _apply_notebook_plan(self, bridge, plan, only_path=None):
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
            write_remote = lambda rel, text: self._write_mirror_file(target_dir, rel, text)
        elif protocol == "webdav":
            root_url = self._webdav_root_url(cfg)
            sub_dir = self._resolve_webdav_dir(cfg).strip().strip("/")
            full_sub = "/".join(p for p in (sub_dir, subdir.strip("/")) if p)
            if full_sub:
                self._webdav_ensure_dir(root_url, full_sub)
            write_remote = lambda rel, text: self._webdav_put_text(base_url, rel, text)
        else:
            os.makedirs(target_dir, exist_ok=True)
            write_remote = lambda rel, text: self._write_mirror_file(target_dir, rel, text)

        pushed = 0
        pulled = 0
        conflict_count = 0
        prefix = f"{plan.get('nb_label')}/" if subdir else ""

        for rel_path in plan["synced"]:
            base_map[rel_path] = sha256_text(local_notes[rel_path])

        for rel_path in plan["to_push_new"]:
            text = local_notes[rel_path]
            write_remote(rel_path, text)
            base_map[rel_path] = sha256_text(text)
            pushed += 1
            self._append_log(f"推送 {prefix}{rel_path}", "成功", tone="success", tooltip=f"已推送到{self._protocol_label(protocol)}")

        for rel_path in plan["to_push_overwrite"]:
            text = local_notes[rel_path]
            write_remote(rel_path, text)
            base_map[rel_path] = sha256_text(text)
            pushed += 1
            self._append_log(f"本地覆盖 {prefix}{rel_path}", "成功", tone="success", tooltip=f"本地优先覆盖{self._protocol_label(protocol)}")

        for rel_path in plan["to_pull_new"]:
            text = remote_notes[rel_path]
            self._write_local_note(bridge, rel_path, text, nb_root=nb_root)
            base_map[rel_path] = sha256_text(text)
            pulled += 1
            self._append_log(f"拉取 {prefix}{rel_path}", "成功", tone="success", tooltip=f"已从{self._protocol_label(protocol)}拉取")

        for rel_path in plan["to_pull_overwrite"]:
            text = remote_notes[rel_path]
            self._write_local_note(bridge, rel_path, text, nb_root=nb_root)
            base_map[rel_path] = sha256_text(text)
            pulled += 1
            self._append_log(f"远端覆盖 {prefix}{rel_path}", "成功", tone="success", tooltip=f"{self._protocol_label(protocol)}优先更新本地")

        for rel_path, conflict_rel, remote_text in plan["conflicts"]:
            local_text = local_notes[rel_path]
            self._write_local_note(bridge, conflict_rel, remote_text, nb_root=nb_root)
            write_remote(conflict_rel, remote_text)
            write_remote(rel_path, local_text)
            base_map[rel_path] = sha256_text(local_text)
            base_map[conflict_rel] = sha256_text(remote_text)
            conflict_count += 1
            self._append_log(f"冲突保留 {prefix}{rel_path}", "冲突副本", tone="warning", tooltip=f"已保留副本 {conflict_rel}")

        asset_count = 0
        if only_path is None:
            if protocol == "webdav":
                asset_count = self._sync_webdav_assets(base_url, nb_root=nb_root)
            else:
                asset_count = self._sync_local_dir_assets(target_dir, nb_root=nb_root)
            if asset_count > 0:
                self._append_log(f"{prefix}同步 {asset_count} 个附件", "成功", tone="success")

        self.sync_meta[plan["meta_key"]] = base_map
        return pushed, pulled, conflict_count, asset_count

    def _compute_batch_plan(self, bridge, cfg, notebooks, only_path=None, inspect_remote=True, force_refresh=False):
        protocol = cfg.get("protocol", "local_mirror")
        target_display = self._target_display(cfg)
        if protocol == "local_mirror":
            target_base = self._resolve_mirror_dir(cfg)
        elif protocol == "webdav":
            target_base = self._webdav_base_url(cfg) or "unconfigured"
        else:
            target_base = f"{self._resolve_local_git_dir(cfg)}:{self._git_branch(cfg)}"

        all_selected = self._selected_notebooks(cfg)
        subdir_map = self._notebook_subdir_map(all_selected or notebooks, protocol, target_base)

        prepared_repo_dir = None
        if protocol == "git" and inspect_remote:
            ok, res = self._prepare_git_repo(cfg, allow_init_or_clone=True, allow_pull=True)
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
            sub = subdir_map.get(nb, "")
            plan = self._compute_sync_plan(
                bridge,
                cfg,
                only_path=only_path,
                inspect_remote=inspect_remote,
                force_refresh=force_refresh,
                nb_root=nb,
                subdir=sub,
                prepared_repo_dir=prepared_repo_dir,
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
            "remote_error": None,
            "fingerprint": fp,
        }

    def _execute_batch_plan(self, bridge, batch, only_path=None):
        protocol = batch["protocol"]
        cfg = batch["cfg"]
        total_pushed = 0
        total_pulled = 0
        total_conflicts = 0
        total_assets = 0

        for plan in batch["plans"]:
            pushed, pulled, conflicts, assets = self._apply_notebook_plan(bridge, plan, only_path=only_path)
            total_pushed += pushed
            total_pulled += pulled
            total_conflicts += conflicts
            total_assets += assets

        did_push = False
        if protocol == "git" and batch.get("repo_root"):
            did_push = self._commit_and_push_git(batch["repo_root"], cfg)

        self._remote_preview_cache.clear()
        total_notes = total_pushed + total_pulled + total_conflicts
        self.stats["total_synced"] += total_notes
        self.stats["last_sync"] = now_hms()

        nb_count = len(batch["plans"])
        nb_prefix = f"{nb_count} 个笔记本 · " if nb_count > 1 else ""

        if total_notes == 0 and total_assets == 0:
            if did_push:
                summary = "已将本地 Git 待推送提交同步到远端"
                self._append_log(f"推送 {self._protocol_label(protocol)} 提交", "成功", tone="success", tooltip=summary)
                self._record_result("成功", summary, protocol=protocol, target=batch["target_display"])
                return summary
            summary = f"{nb_prefix}{self._protocol_label(protocol)}已是最新状态"
            if only_path is None:
                self._append_log(f"{self._protocol_label(protocol)}同步", "无变更", tone="info", tooltip=summary)
            self._record_result("无变更", summary, protocol=protocol, target=batch["target_display"])
            return summary

        summary = f"{nb_prefix}推送 {total_pushed} 篇 · 拉取 {total_pulled} 篇 · 冲突 {total_conflicts} 篇"
        if total_assets > 0:
            summary += f" · 附件 {total_assets} 个"
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
        return f"已完成{self._protocol_label(protocol)}同步：{summary}"

    # ---------- Dispatch & UI ----------

    def _build_pending_confirm(self, batch, reasons):
        sample_lines = []
        multi = len(batch["plans"]) > 1
        for plan in batch["plans"]:
            prefix = f"{plan['nb_label']}/" if multi else ""
            sample_lines.extend(
                [f"[覆盖本地] {prefix}{p}" for p in plan["to_pull_overwrite"]]
                + [f"[覆盖远端] {prefix}{p}" for p in plan["to_push_overwrite"]]
                + [f"[冲突副本] {prefix}{p} -> {cr}" for p, cr, _ in plan["conflicts"]]
                + [f"[拉取] {prefix}{p}" for p in plan["to_pull_new"]]
                + [f"[推送] {prefix}{p}" for p in plan["to_push_new"]]
                + [f"[远端缺失] {prefix}{p}" for p in plan["remote_missing"]]
                + [f"[本地缺失] {prefix}{p}" for p in plan["local_missing"]]
            )
        return {
            "scope_key": self._result_key(),
            "fingerprint": batch["fingerprint"],
            "protocol": batch["protocol"],
            "target_display": batch["target_display"],
            "reasons": list(reasons),
            "badge": f"需确认 · {len(reasons)} 项风险",
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

    def _run_sync(self, bridge, only_path=None, only_nb_root=None, confirmed=False, approved_batch=None):
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
                msg = "请至少选择一个笔记本"
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
                msg = f"{self._protocol_label(protocol)}同步未完成: {sanitize_error_text(exc)}"
                self._append_log(f"{self._protocol_label(protocol)}同步", "失败", tone="danger", tooltip=msg)
                self._record_result("失败", msg, protocol=protocol)
                self._save_runtime(bridge)
                self.last_status = msg
                raise RuntimeError(msg) from exc

        if batch.get("remote_error"):
            msg = batch["remote_error"]
            self._append_log(f"{self._protocol_label(protocol)}同步", "失败", tone="danger", tooltip=msg)
            self._record_result("失败", msg, protocol=protocol, target=batch["target_display"])
            self._save_runtime(bridge)
            self.last_status = msg
            raise RuntimeError(msg)

        if not confirmed:
            reasons = self._assess_batch_dangerous_changes(batch, self.config, saved_path=only_path)
            if reasons:
                if only_path is not None:
                    msg = f"自动同步暂停（{reasons[0]}），请点击立即同步确认"
                    self._append_log(f"自动同步暂停 ({only_path})", "待确认", tone="warning", tooltip=msg)
                    self._record_result("待确认", msg, protocol=protocol, target=batch["target_display"])
                    self._save_runtime(bridge)
                    self.last_status = msg
                    return msg
                self.pending_confirm = self._build_pending_confirm(batch, reasons)
                msg = "检测到危险变更，请先确认后执行"
                self._append_log(reasons[0], "待确认", tone="warning", tooltip=msg)
                self._record_result("待确认", reasons[0], protocol=protocol, target=batch["target_display"])
                self._save_runtime(bridge)
                self.last_status = msg
                return msg

        try:
            msg = self._execute_batch_plan(bridge, batch, only_path=only_path)
        except Exception as exc:
            msg = sanitize_error_text(exc)
            if not msg.startswith(self._protocol_label(protocol)) and "Git" not in msg:
                msg = f"{self._protocol_label(protocol)}同步未完成: {msg}"
            self._append_log(f"{self._protocol_label(protocol)}同步", "失败", tone="danger", tooltip=msg)
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
            f"测试连接 ({self._protocol_label(protocol)})",
            "通过" if ok else "未连通",
            tone="success" if ok else "danger",
            tooltip=msg,
        )
        self.last_status = msg
        return bool(ok), msg

    def _confirmation_card(self):
        pending = self.pending_confirm
        lines = [f"[风险] {reason}" for reason in pending["reasons"]]
        samples = pending["sample_lines"]
        remaining = 9 - len(lines)
        lines.extend(samples[:remaining])
        if len(samples) > remaining:
            lines.append(f"… 其余 {len(samples) - remaining} 项变更")
        return {
            "id": "preview-card",
            "title": "确认同步变更",
            "items": [
                {
                    "kind": "preview",
                    "preview": {
                        "variant": "plan",
                        "palette": "warm",
                        "title": self._protocol_label(pending["protocol"]),
                        "body": "\n".join(lines),
                    },
                },
                {
                    "kind": "actions",
                    "buttons": [
                        {"id": "confirm_sync", "label": "确认同步", "variant": "danger"},
                        {"id": "cancel_confirm", "label": "取消", "variant": "secondary"},
                    ],
                },
            ],
        }

    def _conflict_policy_item(self, c):
        return {
            "kind": "segmented",
            "id": "conflict_policy",
            "label": "双端冲突处理",
            "value": c["conflict_policy"],
            "options": [
                {"value": "keep_both", "label": "生成冲突副本"},
                {"value": "local_first", "label": "优先本地"},
                {"value": "remote_first", "label": "优先远端"},
            ],
        }

    def _build_legacy_page(self, c):
        protocol = c["protocol"]

        target_items = [
            {
                "kind": "segmented",
                "id": "protocol",
                "label": "同步方式",
                "value": protocol,
                "options": [
                    {"value": "local_mirror", "label": "目录镜像"},
                    {"value": "webdav", "label": "WebDAV"},
                    {"value": "git", "label": "Git 仓库"},
                ],
            },
            {
                "kind": "folder",
                "id": "mirror_dir",
                "label": "同步文件夹",
                "value": self._resolve_mirror_dir(c),
                "visible_when": {"control_id": "protocol", "equals": "local_mirror"},
            },
        ]
        for kind, key, label, placeholder in (
            ("input", "webdav_url", "服务器地址", "https://dav.example.com"),
            ("input", "webdav_dir", "远端目录", "/BlockNotes"),
            ("input", "webdav_user", "用户名", ""),
            ("secret", "webdav_pass", "密码", ""),
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
                "label": "仓库地址",
                "value": c["git_remote"],
                "placeholder": "git@github.com:user/notes.git",
                "visible_when": {"control_id": "protocol", "equals": "git"},
            },
            {
                "kind": "input",
                "id": "git_branch",
                "label": "分支",
                "value": c["git_branch"],
                "placeholder": "main",
                "visible_when": {"control_id": "protocol", "equals": "git"},
            },
            {
                "kind": "segmented",
                "id": "git_auth",
                "label": "认证方式",
                "value": c["git_auth"],
                "options": [
                    {"value": "ssh", "label": "SSH"},
                    {"value": "token", "label": "HTTPS 令牌"},
                ],
                "visible_when": {"control_id": "protocol", "equals": "git"},
            },
        ])
        if protocol == "git":
            target_items.append({
                "kind": "secret",
                "id": "git_token",
                "label": "访问令牌",
                "value": c["git_token"],
                "visible_when": {"control_id": "git_auth", "equals": "token"},
            })
        target_items.extend([
            self._conflict_policy_item(c),
            {
                "kind": "switch",
                "id": "auto_sync",
                "label": "保存笔记后自动同步",
                "value": c["auto_sync"],
            },
            {
                "kind": "actions",
                "visible_when": {"control_id": "protocol", "in": ["webdav", "git"]},
                "buttons": [
                    {"id": "test_conn", "label": "测试连接", "variant": "secondary"},
                    {"id": "save_config", "label": "保存", "variant": "primary"},
                ],
            },
        ])
        return [{"id": "target-card", "title": "同步设置", "items": target_items}]

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
                    opt["badge"] = "当前"
                nb_options.append(opt)

            nb_meta = f"已选 {len(selected)} / {len(nb_options)}" if nb_options else ""
            notebooks_card = {
                "id": "notebooks-card",
                "title": "同步笔记本",
                "meta": nb_meta,
                "items": [
                    {
                        "kind": "checklist",
                        "id": "selected_notebooks",
                        "value": selected,
                        "options": nb_options,
                        "empty_text": "暂无已打开的笔记本",
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
                        {"value": "local_mirror", "label": "目录镜像"},
                        {"value": "webdav", "label": "WebDAV"},
                        {"value": "git", "label": "Git 仓库"},
                    ],
                },
                {
                    "kind": "folder",
                    "id": "mirror_dir",
                    "label": "目标文件夹",
                    "layout": "stacked",
                    "value": self._resolve_mirror_dir(c),
                    "visible_when": {"control_id": "protocol", "equals": "local_mirror"},
                },
                {
                    "kind": "input",
                    "id": "webdav_url",
                    "label": "服务器地址",
                    "layout": "stacked",
                    "value": c["webdav_url"],
                    "placeholder": "https://dav.example.com",
                    "visible_when": {"control_id": "protocol", "equals": "webdav"},
                },
                {
                    "kind": "input",
                    "id": "webdav_dir",
                    "label": "远端目录",
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
                            "label": "用户名",
                            "layout": "stacked",
                            "value": c["webdav_user"],
                            "placeholder": "账号",
                        },
                        {
                            "kind": "secret",
                            "id": "webdav_pass",
                            "label": "密码",
                            "layout": "stacked",
                            "value": c["webdav_pass"],
                            "placeholder": "应用密码或口令",
                        },
                    ],
                },
                {
                    "kind": "input",
                    "id": "git_remote",
                    "label": "仓库地址",
                    "layout": "stacked",
                    "value": c["git_remote"],
                    "placeholder": "git@github.com:user/notes.git",
                    "visible_when": {"control_id": "protocol", "equals": "git"},
                },
                {
                    "kind": "input",
                    "id": "git_branch",
                    "label": "分支",
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
                            "label": "认证方式",
                            "layout": "stacked",
                            "value": c["git_auth"],
                            "options": [
                                {"value": "ssh", "label": "SSH"},
                                {"value": "token", "label": "HTTPS 令牌"},
                            ],
                        },
                        {
                            "kind": "secret",
                            "id": "git_token",
                            "label": "访问令牌",
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
                        {"id": "test_conn", "label": "测试连接", "variant": "secondary"},
                        {"id": "save_config", "label": "保存", "variant": "primary"},
                    ],
                },
            ]

            target_card = {
                "id": "target-card",
                "title": "同步目标",
                "items": target_items,
            }
            options_card = {
                "id": "options-card",
                "title": "同步选项",
                "items": [
                    self._conflict_policy_item(c),
                    {
                        "kind": "switch",
                        "id": "auto_sync",
                        "label": "保存笔记后自动同步",
                        "value": c["auto_sync"],
                    },
                ],
            }
            cards = [notebooks_card, target_card, options_card]
        else:
            cards = self._build_legacy_page(c)

        if self.pending_confirm and self.pending_confirm.get("scope_key") == self._result_key() and c == self.config:
            cards.append(self._confirmation_card())

        configured = not self._target_error(c)
        last_result = self._get_last_result() or {}
        last_ok = last_result.get("last_success")
        history_meta = (
            f"上次成功 {last_ok['time']}"
            if isinstance(last_ok, dict) and last_ok.get("time")
            else ""
        )
        history_entries = [
            self._normalize_log(entry)
            for entry in self.logs[:6]
            if isinstance(entry, dict)
        ]
        cards.append({
            "id": "history-card",
            "title": "最近同步记录",
            "meta": history_meta,
            "items": [
                {
                    "kind": "log_list",
                    "id": "sync_logs",
                    "empty_text": "暂无同步记录",
                    "entries": history_entries,
                }
            ],
        })

        status = self.last_status
        if not status and configured and c == self.config:
            if isinstance(last_ok, dict) and last_ok.get("time"):
                status = f"上次同步 {last_ok['time']}"
            elif last_result.get("summary"):
                status = str(last_result["summary"])
        return {
            "title": "同步",
            "status": status,
            "header_actions": [
                {"id": "sync_now", "label": "立即同步", "variant": "primary"},
            ] if configured else [],
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
            raw_nbs = params.get("notebooks")
            if isinstance(raw_nbs, list):
                self.known_notebooks = [str(p) for p in raw_nbs if str(p or "").strip()]
            self._load_state(bridge)
            return {"ready": True}

        if method == "plugin.render":
            self._refresh_known_notebooks(bridge)
            values = params.get("values")
            render_status = ""
            if isinstance(values, dict) and values:
                cfg = self._normalize_config(values, base=self.config)
                changed_immediate = False
                if "selected_notebooks" in values and cfg["selected_notebooks"] != self.config["selected_notebooks"]:
                    self.config["selected_notebooks"] = list(cfg["selected_notebooks"])
                    self.pending_confirm = None
                    self._remote_preview_cache.clear()
                    self.last_status = ""
                    changed_immediate = True
                if cfg["auto_sync"] != self.config["auto_sync"]:
                    self.config["auto_sync"] = cfg["auto_sync"]
                    changed_immediate = True
                if cfg["conflict_policy"] != self.config["conflict_policy"]:
                    self.config["conflict_policy"] = cfg["conflict_policy"]
                    self.pending_confirm = None
                    self._remote_preview_cache.clear()
                    self.last_status = ""
                    changed_immediate = True
                if cfg["protocol"] == "local_mirror":
                    mirror_err = self._target_error(cfg, require_notebooks=False)
                    if not mirror_err:
                        if self.config["protocol"] != "local_mirror" or self.config["mirror_dir"] != cfg["mirror_dir"]:
                            self.config["protocol"] = "local_mirror"
                            self.config["mirror_dir"] = cfg["mirror_dir"]
                            self.pending_confirm = None
                            self._remote_preview_cache.clear()
                            self.last_status = "已启用本地镜像目录"
                            changed_immediate = True
                    elif cfg["mirror_dir"]:
                        render_status = mirror_err
                if changed_immediate:
                    self._save_config(bridge)
            else:
                cfg = dict(self.config)
                cfg["selected_notebooks"] = list(self.config.get("selected_notebooks") or [])
            page = self.build_page(cfg=cfg)
            if render_status:
                page["status"] = render_status
            return {"page": page}

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
                    self.pending_confirm = None
                    self._remote_preview_cache.clear()
                self.config = next_cfg
                self._save_config(bridge)
                status = "已保存同步目标配置"
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
                        self.pending_confirm = None
                        self._remote_preview_cache.clear()
                        self.config = next_cfg
                        self._save_config(bridge)
                err = self._target_error(self.config)
                if err or not self._selected_notebooks(self.config):
                    status = err or "请至少选择一个笔记本"
                    self.last_status = status
                    ok = False
                    tone = "danger"
                else:
                    self.pending_confirm = None
                    status = self._run_sync(bridge)
                    if self.pending_confirm:
                        ok = True
                        tone = "warning"
                    else:
                        ok = True
                        tone = "success"
            elif action_id == "confirm_sync":
                pc = self.pending_confirm
                if not pc or pc.get("scope_key") != self._result_key():
                    status = "当前没有待确认的同步计划"
                    self.last_status = status
                    ok = False
                    tone = "warning"
                else:
                    protocol = self.config.get("protocol", "local_mirror")
                    notebooks = self._selected_notebooks(self.config)
                    try:
                        batch = self._compute_batch_plan(bridge, self.config, notebooks, inspect_remote=True, force_refresh=True)
                    except Exception as exc:
                        msg = f"{self._protocol_label(protocol)}同步未完成: {sanitize_error_text(exc)}"
                        self._append_log(f"{self._protocol_label(protocol)}同步", "失败", tone="danger", tooltip=msg)
                        self._record_result("失败", msg, protocol=protocol)
                        self._save_runtime(bridge)
                        self.last_status = msg
                        raise RuntimeError(msg) from exc

                    if batch.get("remote_error"):
                        msg = batch["remote_error"]
                        self._append_log(f"{self._protocol_label(batch['protocol'])}同步", "失败", tone="danger", tooltip=msg)
                        self._record_result("失败", msg, protocol=batch["protocol"], target=batch["target_display"])
                        self._save_runtime(bridge)
                        self.last_status = msg
                        raise RuntimeError(msg)

                    if batch["fingerprint"] != pc.get("fingerprint"):
                        reasons = self._assess_batch_dangerous_changes(batch, self.config)
                        if reasons:
                            self.pending_confirm = self._build_pending_confirm(batch, reasons)
                            self._append_log(reasons[0], "待确认", tone="warning", tooltip="同步计划已变化，请重新确认")
                            self._record_result("待确认", "同步计划已变化，请重新确认", protocol=batch["protocol"], target=batch["target_display"])
                            self._save_runtime(bridge)
                            status = "同步计划已变化，请重新确认"
                            self.last_status = status
                            ok = False
                            tone = "warning"
                        else:
                            self.pending_confirm = None
                            self._append_log("同步计划已变化", "待确认", tone="warning", tooltip="原危险变更已消除，请重新同步")
                            self._record_result("待确认", "同步计划已变化，请重新同步", protocol=batch["protocol"], target=batch["target_display"])
                            self._save_runtime(bridge)
                            status = "同步计划已变化，请重新同步"
                            self.last_status = status
                            ok = False
                            tone = "warning"
                    else:
                        self.pending_confirm = None
                        err = self._target_error(self.config)
                        if err or not self._selected_notebooks(self.config):
                            status = err or "请至少选择一个笔记本"
                            self.last_status = status
                            ok = False
                            tone = "danger"
                        else:
                            status = self._run_sync(bridge, confirmed=True, approved_batch=batch)
                            ok = True
                            tone = "success"
            elif action_id == "cancel_confirm":
                self.pending_confirm = None
                self._append_log("危险变更同步", "已取消", tone="info", tooltip="用户已取消本次同步")
                self._record_result("已取消", "用户已取消危险变更")
                self._save_runtime(bridge)
                status = "已取消本次同步"
                self.last_status = status
                ok = True
                tone = "info"
            else:
                status = "已完成操作"
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
    HostBridge().serve(plugin.handle)


if __name__ == "__main__":
    main()
