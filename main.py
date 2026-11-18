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
VALID_MIRROR_PRESETS = ("downloads", "documents", "custom")
VALID_WEBDAV_DIR_PRESETS = ("/BlockNotes", "/Notes", "/Markdown", "custom")
VALID_GIT_BRANCH_PRESETS = ("main", "master", "custom")
VALID_SYNC_INTERVALS = ("manual", "5m", "30m")
VALID_CONFLICT_POLICIES = ("keep_both", "remote_first", "local_first")
VALID_GIT_AUTHS = ("ssh", "token")
DELETE_GUARD_THRESHOLD = 5
MAX_LOG_ENTRIES = 20

DEFAULT_CONFIG = {
    "protocol": "local_mirror",
    "mirror_preset": "downloads",
    "mirror_dir": "",
    "sync_scope": "all",
    "webdav_url": "",
    "webdav_dir_preset": "/BlockNotes",
    "webdav_dir": "/BlockNotes",
    "webdav_user": "",
    "webdav_pass": "",
    "git_remote": "",
    "git_branch_preset": "main",
    "git_branch": "main",
    "git_auth": "ssh",
    "git_token": "",
    "auto_sync": True,
    "sync_interval": "manual",
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
        self.locale = "zh"
        self.config = dict(DEFAULT_CONFIG)
        self.notebook_configs = {}
        self.notebook_results = {}
        self.stats = {"total_synced": 0, "last_sync": ""}
        self.logs = []
        self.sync_meta = {}
        self.pending_confirm = None
        self._remote_preview_cache = {}
        self.last_status = "目录镜像 · 已就绪"

    def _notebook_key(self):
        raw = (self.notebook_root or "").strip()
        if not raw:
            return "default"
        return os.path.normpath(os.path.expanduser(raw))

    def _notebook_label(self):
        key = self._notebook_key()
        if key == "default":
            return "默认笔记本"
        return os.path.basename(key) or key

    def _notebook_slug(self):
        key = self._notebook_key()
        if key == "default":
            return "default"
        base = os.path.basename(key) or "notebook"
        safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in base).strip("-") or "notebook"
        return f"{safe[:24]}-{sha256_text(key)[:8]}"

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
        nb_key = self._notebook_key()
        nb_cfgs_res = bridge.call_host("host.storage.get", {"key": "notebook_configs"})
        if nb_cfgs_res.get("found") and isinstance(nb_cfgs_res.get("value"), dict):
            self.notebook_configs = {
                str(k): self._normalize_config(v, base=DEFAULT_CONFIG)
                for k, v in nb_cfgs_res["value"].items()
                if isinstance(v, dict)
            }

        cfg_res = bridge.call_host("host.storage.get", {"key": "config"})
        if nb_key in self.notebook_configs:
            self.config = self._normalize_config(self.notebook_configs[nb_key], base=DEFAULT_CONFIG)
        elif not self.notebook_configs and cfg_res.get("found") and isinstance(cfg_res.get("value"), dict):
            self.config = self._normalize_config(cfg_res["value"], base=DEFAULT_CONFIG)
            self.notebook_configs[nb_key] = dict(self.config)
        else:
            self.config = dict(DEFAULT_CONFIG)

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
        self.last_status = f"{self._protocol_label(self.config['protocol'])} · 已就绪"

    def _normalize_log(self, entry):
        title = str(entry.get("title") or "同步事件").strip() or "同步事件"
        time_str = str(entry.get("time") or now_hms()).strip() or now_hms()
        status = str(entry.get("status") or "").strip()
        item = {"title": title, "time": time_str}
        if status:
            item["status"] = status
        return item

    def _normalize_config(self, raw, base=None):
        merged = dict(DEFAULT_CONFIG)
        merged.update(base if base is not None else self.config)
        if not isinstance(raw, dict):
            return merged

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
                merged[key] = val if key in ("webdav_pass", "git_token") else val.strip()

        mirror_preset = raw.get("mirror_preset")
        if mirror_preset in VALID_MIRROR_PRESETS:
            merged["mirror_preset"] = mirror_preset
        elif "mirror_preset" not in raw and merged["mirror_dir"]:
            merged["mirror_preset"] = "custom"

        webdav_dir_preset = raw.get("webdav_dir_preset")
        if webdav_dir_preset in VALID_WEBDAV_DIR_PRESETS:
            merged["webdav_dir_preset"] = webdav_dir_preset
        elif "webdav_dir_preset" not in raw and merged["webdav_dir"]:
            merged["webdav_dir_preset"] = (
                merged["webdav_dir"]
                if merged["webdav_dir"] in ("/BlockNotes", "/Notes", "/Markdown")
                else "custom"
            )

        git_branch_preset = raw.get("git_branch_preset")
        if git_branch_preset in VALID_GIT_BRANCH_PRESETS:
            merged["git_branch_preset"] = git_branch_preset
        elif "git_branch_preset" not in raw and merged["git_branch"]:
            merged["git_branch_preset"] = (
                merged["git_branch"]
                if merged["git_branch"] in ("main", "master")
                else "custom"
            )

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

        sync_interval = raw.get("sync_interval", merged["sync_interval"])
        if sync_interval in VALID_SYNC_INTERVALS:
            merged["sync_interval"] = sync_interval

        policy = raw.get("conflict_policy", merged["conflict_policy"])
        if policy in VALID_CONFLICT_POLICIES:
            merged["conflict_policy"] = policy

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

    def _record_result(self, status, summary, protocol=None, target="", pushed=0, pulled=0, conflicts=0, assets=0):
        nb_key = self._notebook_key()
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
        return self.notebook_results.get(self._notebook_key())

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

    def _append_log(self, title, status):
        entry = {"title": str(title) or "同步任务", "time": now_hms(), "status": str(status) or "完成"}
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
        preset = c.get("mirror_preset", "downloads")
        if preset == "downloads":
            return os.path.join(self._downloads_root(), "Block-Sync")
        if preset == "documents":
            return os.path.join(os.path.normpath(os.path.expanduser("~/Documents")), "Block-Sync")
        raw = str(c.get("mirror_dir") or "").strip()
        if not raw:
            return os.path.join(self._downloads_root(), "Block-Sync")
        expanded = os.path.expanduser(raw)
        if os.path.isabs(expanded):
            return os.path.normpath(expanded)
        return os.path.normpath(os.path.join(self._downloads_root(), expanded))

    def _resolve_webdav_dir(self, cfg=None):
        c = cfg or self.config
        preset = c.get("webdav_dir_preset", "/BlockNotes")
        if preset in ("/BlockNotes", "/Notes", "/Markdown"):
            return preset
        raw = str(c.get("webdav_dir") or "").strip()
        return raw or "/BlockNotes"

    def _matches_scope(self, rel_path, scope=None):
        sc = scope if scope is not None else self.config.get("sync_scope", "all")
        if not sc or sc == "all":
            return True
        return rel_path.startswith(f"{sc}/")

    def _list_local_note_paths(self, bridge):
        listed = bridge.call_host("host.notes.list", {}).get("notes") or []
        paths = []
        for item in listed:
            rel_path = str(item.get("path") or "").replace("\\", "/")
            if is_safe_rel_md(rel_path):
                paths.append(rel_path)
        return sorted(set(paths))

    def _extract_top_dirs(self, paths):
        dirs = {p.split("/", 1)[0] for p in paths if "/" in p}
        return sorted(dirs)

    def _read_local_notes(self, bridge, only_path=None, scope=None, paths=None):
        notes = {}
        all_paths = paths if paths is not None else self._list_local_note_paths(bridge)
        for rel_path in all_paths:
            if not is_safe_rel_md(rel_path):
                continue
            if only_path and rel_path != only_path:
                continue
            if not only_path and not self._matches_scope(rel_path, scope):
                continue
            res = bridge.call_host("host.notes.read", {"path": rel_path})
            notes[rel_path] = str(res.get("content") or "")
        return notes

    def _read_local_assets(self):
        assets = {}
        if not self.notebook_root:
            return assets
        root_real = os.path.realpath(self.notebook_root)
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

    def _write_local_asset(self, rel_asset_path, data):
        if not self.notebook_root or not is_safe_rel_asset(rel_asset_path):
            return False
        root_real = os.path.realpath(self.notebook_root)
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

    def _sync_local_dir_assets(self, remote_dir):
        if not self.config.get("sync_assets", True) or not self.notebook_root:
            return 0
        local_assets = self._read_local_assets()
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
                if self._write_local_asset(rel, remote_assets[rel]):
                    synced += 1
            elif sha256_bytes(local_assets[rel]) != sha256_bytes(remote_assets[rel]):
                if policy == "remote_first":
                    if self._write_local_asset(rel, remote_assets[rel]):
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
            self._append_log("删除保护暂停", guard_msg)
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
                self._append_log(rel_path, "已镜像到本地目录")
            elif in_remote and not in_local:
                text = remote_notes[rel_path]
                bridge.call_host("host.notes.write", {"path": rel_path, "content": text})
                base_map[rel_path] = sha256_text(text)
                synced_count += 1
                self._append_log(rel_path, "已从镜像恢复")
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
                    self._append_log(rel_path, "本地优先覆盖镜像")
                elif action == "pull":
                    bridge.call_host("host.notes.write", {"path": rel_path, "content": chosen_text})
                    base_map[rel_path] = new_hash
                    synced_count += 1
                    self._append_log(rel_path, "镜像优先更新本地")
                elif action == "keep_both":
                    conflict_rel, conflict_text = conflict_extra
                    bridge.call_host("host.notes.write", {"path": conflict_rel, "content": conflict_text})
                    self._write_mirror_file(mirror_dir, conflict_rel, conflict_text)
                    self._write_mirror_file(mirror_dir, rel_path, chosen_text)
                    base_map[rel_path] = new_hash
                    base_map[conflict_rel] = sha256_text(conflict_text)
                    synced_count += 1
                    self._append_log(rel_path, f"冲突已保留副本 {conflict_rel}")

        asset_count = self._sync_local_dir_assets(mirror_dir)
        if asset_count > 0:
            self._append_log("assets 附件同步", f"同步 {asset_count} 个文件")

        self.sync_meta[meta_key] = base_map
        self.stats["total_synced"] += synced_count
        self.stats["last_sync"] = now_hms()
        if synced_count == 0 and asset_count == 0 and not all_paths:
            return "当前笔记本暂无笔记，镜像目录已就绪"
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

    def _webdav_base_url(self, cfg=None):
        root = self._webdav_root_url(cfg)
        if not root:
            return ""
        sub = self._resolve_webdav_dir(cfg).strip().strip("/")
        if not sub:
            return root
        parts = [urllib.parse.quote(p) for p in sub.split("/") if p and p not in (".", "..")]
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

    def _sync_webdav_assets(self, base_url):
        if not self.config.get("sync_assets", True) or not self.notebook_root:
            return 0
        local_assets = self._read_local_assets()
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
                if self._write_local_asset(rel, remote_assets[rel]):
                    synced += 1
            elif sha256_bytes(local_assets[rel]) != sha256_bytes(remote_assets[rel]):
                if policy == "remote_first":
                    if self._write_local_asset(rel, remote_assets[rel]):
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
            self._append_log("WebDAV 同步", msg)
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
                self._append_log("删除保护暂停", guard_msg)
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
                    self._append_log(rel_path, "已上传到 WebDAV")
                elif in_remote and not in_local:
                    text = remote_notes[rel_path]
                    bridge.call_host("host.notes.write", {"path": rel_path, "content": text})
                    base_map[rel_path] = sha256_text(text)
                    synced_count += 1
                    self._append_log(rel_path, "已从 WebDAV 下载")
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
                        self._append_log(rel_path, "本地优先上传 WebDAV")
                    elif action == "pull":
                        bridge.call_host("host.notes.write", {"path": rel_path, "content": chosen_text})
                        base_map[rel_path] = new_hash
                        synced_count += 1
                        self._append_log(rel_path, "远端优先更新本地")
                    elif action == "keep_both":
                        conflict_rel, conflict_text = conflict_extra
                        bridge.call_host("host.notes.write", {"path": conflict_rel, "content": conflict_text})
                        self._webdav_put_text(base_url, conflict_rel, conflict_text)
                        self._webdav_put_text(base_url, rel_path, chosen_text)
                        base_map[rel_path] = new_hash
                        base_map[conflict_rel] = sha256_text(conflict_text)
                        synced_count += 1
                        self._append_log(rel_path, f"WebDAV 冲突已保留副本 {conflict_rel}")

            asset_count = 0 if only_path else self._sync_webdav_assets(base_url)
            if asset_count > 0:
                self._append_log("assets 附件同步", f"同步 {asset_count} 个文件")

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
            self._append_log("WebDAV 同步", msg)
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
        preset = c.get("git_branch_preset", "main")
        if preset in ("main", "master"):
            return preset
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
        return os.path.join(self.data_dir or os.getcwd(), "git-repos", self._notebook_slug())

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

    def _fetch_webdav_notes(self, cfg, only_path=None, scope="all", timeout=6, force_refresh=False):
        root_url = self._webdav_root_url(cfg)
        base_url = self._webdav_base_url(cfg)
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

    def _compute_sync_plan(self, bridge, cfg, only_path=None, inspect_remote=True, force_refresh=False):
        protocol = cfg.get("protocol", "local_mirror")
        scope = cfg.get("sync_scope", "all")
        policy = cfg.get("conflict_policy", "keep_both")
        local_notes = self._read_local_notes(bridge, only_path=only_path, scope=scope)
        target_display = self._target_display(cfg)

        remote_notes = {}
        remote_inspected = True
        remote_error = None
        target_dir = ""
        base_url = ""

        if protocol == "local_mirror":
            target_dir = self._resolve_mirror_dir(cfg)
            meta_key = self._meta_key("local_mirror", target_dir)
            legacy_key = f"local_mirror:{target_dir}"
            remote_notes = self._scan_mirror_files(target_dir, only_path=only_path, scope=scope)
        elif protocol == "webdav":
            base_url = self._webdav_base_url(cfg)
            meta_key = self._meta_key("webdav", base_url or "unconfigured")
            legacy_key = f"webdav:{base_url}" if base_url else None
            if not base_url:
                remote_inspected = False
                remote_error = "请先填写有效的 WebDAV http(s) 地址"
            elif inspect_remote or force_refresh:
                ok, fetched, err = self._fetch_webdav_notes(
                    cfg, only_path=only_path, scope=scope, timeout=6 if inspect_remote else 4, force_refresh=force_refresh
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
            repo_dir = self._resolve_local_git_dir(cfg)
            target_dir = repo_dir
            meta_key = self._meta_key("git", f"{repo_dir}:{branch}")
            legacy_key = f"git:{repo_dir}:{branch}"
            if inspect_remote:
                ok, res = self._prepare_git_repo(cfg, allow_init_or_clone=True, allow_pull=True)
                if ok:
                    remote_notes = self._scan_mirror_files(res, only_path=only_path, scope=scope)
                else:
                    remote_inspected = False
                    remote_error = res
            elif os.path.isdir(os.path.join(repo_dir, ".git")):
                remote_notes = self._scan_mirror_files(repo_dir, only_path=only_path, scope=scope)
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
            "nb": self._notebook_key(),
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
            "protocol": protocol,
            "target_display": target_display,
            "target_dir": target_dir,
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

    def _assess_dangerous_changes(self, plan, cfg):
        if not plan.get("remote_inspected"):
            return []
        reasons = []
        n_pull_new = len(plan["to_pull_new"])
        n_pull_ow = len(plan["to_pull_overwrite"])
        n_push_ow = len(plan["to_push_overwrite"])
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

    def _execute_sync_plan(self, bridge, plan, only_path=None):
        protocol = plan["protocol"]
        cfg = plan["cfg"]
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
            if sub_dir:
                self._webdav_ensure_dir(root_url, sub_dir)
            write_remote = lambda rel, text: self._webdav_put_text(base_url, rel, text)
        else:
            write_remote = lambda rel, text: self._write_mirror_file(target_dir, rel, text)

        pushed = 0
        pulled = 0
        conflict_count = 0

        for rel_path in plan["synced"]:
            base_map[rel_path] = sha256_text(local_notes[rel_path])

        for rel_path in plan["to_push_new"]:
            text = local_notes[rel_path]
            write_remote(rel_path, text)
            base_map[rel_path] = sha256_text(text)
            pushed += 1
            self._append_log(rel_path, f"已推送到{self._protocol_label(protocol)}")

        for rel_path in plan["to_push_overwrite"]:
            text = local_notes[rel_path]
            write_remote(rel_path, text)
            base_map[rel_path] = sha256_text(text)
            pushed += 1
            self._append_log(rel_path, f"本地优先覆盖{self._protocol_label(protocol)}")

        for rel_path in plan["to_pull_new"]:
            text = remote_notes[rel_path]
            bridge.call_host("host.notes.write", {"path": rel_path, "content": text})
            base_map[rel_path] = sha256_text(text)
            pulled += 1
            self._append_log(rel_path, f"已从{self._protocol_label(protocol)}拉取")

        for rel_path in plan["to_pull_overwrite"]:
            text = remote_notes[rel_path]
            bridge.call_host("host.notes.write", {"path": rel_path, "content": text})
            base_map[rel_path] = sha256_text(text)
            pulled += 1
            self._append_log(rel_path, f"{self._protocol_label(protocol)}优先更新本地")

        for rel_path, conflict_rel, remote_text in plan["conflicts"]:
            local_text = local_notes[rel_path]
            bridge.call_host("host.notes.write", {"path": conflict_rel, "content": remote_text})
            write_remote(conflict_rel, remote_text)
            write_remote(rel_path, local_text)
            base_map[rel_path] = sha256_text(local_text)
            base_map[conflict_rel] = sha256_text(remote_text)
            conflict_count += 1
            self._append_log(rel_path, f"冲突已保留副本 {conflict_rel}")

        asset_count = 0
        if only_path is None:
            if protocol == "webdav":
                asset_count = self._sync_webdav_assets(base_url)
            else:
                asset_count = self._sync_local_dir_assets(target_dir)
            if asset_count > 0:
                self._append_log("assets 附件同步", f"同步 {asset_count} 个文件")

        did_push = False
        if protocol == "git":
            branch = self._git_branch(cfg)
            status_proc = self._run_git(["status", "--porcelain"], cwd=target_dir, cfg=cfg)
            if status_proc.returncode != 0:
                err = sanitize_error_text(status_proc.stderr or status_proc.stdout or "git status 失败")
                raise RuntimeError(f"Git 状态检查失败: {err}")

            if status_proc.stdout.strip():
                add_proc = self._run_git(["add", "-A"], cwd=target_dir, cfg=cfg)
                if add_proc.returncode != 0:
                    err = sanitize_error_text(add_proc.stderr or add_proc.stdout or "git add 失败")
                    raise RuntimeError(f"Git 暂存失败: {err}")

                commit_proc = self._run_git(
                    [
                        "-c", "user.name=Block Sync",
                        "-c", "user.email=sync@blockmd.local",
                        "commit", "-m", "sync: update markdown notes",
                    ],
                    cwd=target_dir,
                    cfg=cfg,
                )
                if commit_proc.returncode != 0:
                    self._run_git(["reset"], cwd=target_dir, cfg=cfg)
                    err = sanitize_error_text(commit_proc.stderr or commit_proc.stdout or "git commit 失败")
                    raise RuntimeError(f"Git 提交失败: {err}")

            remote_proc = self._run_git(["remote"], cwd=target_dir, cfg=cfg)
            if remote_proc.returncode != 0:
                err = sanitize_error_text(remote_proc.stderr or remote_proc.stdout or "git remote 失败")
                raise RuntimeError(f"Git 远端检查失败: {err}")

            remotes = [r.strip() for r in remote_proc.stdout.splitlines() if r.strip()]
            if remotes:
                remote_name = "origin" if "origin" in remotes else remotes[0]
                head_proc = self._run_git(["rev-parse", "--verify", "HEAD"], cwd=target_dir, cfg=cfg)
                if head_proc.returncode == 0:
                    needs_push = False
                    ref_proc = self._run_git(
                        ["rev-parse", "--verify", f"refs/remotes/{remote_name}/{branch}"],
                        cwd=target_dir,
                        cfg=cfg,
                    )
                    if ref_proc.returncode != 0:
                        needs_push = True
                    else:
                        ahead_proc = self._run_git(
                            ["rev-list", "--count", f"refs/remotes/{remote_name}/{branch}..HEAD"],
                            cwd=target_dir,
                            cfg=cfg,
                        )
                        if ahead_proc.returncode != 0 or int((ahead_proc.stdout or "0").strip() or "0") > 0:
                            needs_push = True

                    if needs_push:
                        push_proc = self._run_git(
                            ["push", "-u", remote_name, f"HEAD:{branch}"],
                            cwd=target_dir,
                            timeout=10,
                            cfg=cfg,
                        )
                        if push_proc.returncode != 0:
                            self.sync_meta[plan["meta_key"]] = base_map
                            self.stats["total_synced"] += pushed + pulled + conflict_count
                            err = sanitize_error_text(push_proc.stderr or push_proc.stdout or "push 失败")
                            raise RuntimeError(f"已提交到本地 Git，但远端推送未完成: {err}")
                        did_push = True

        self._remote_preview_cache.clear()
        self.sync_meta[plan["meta_key"]] = base_map
        total_notes = pushed + pulled + conflict_count
        self.stats["total_synced"] += total_notes
        self.stats["last_sync"] = now_hms()

        if total_notes == 0 and asset_count == 0:
            if did_push:
                summary = "已将本地 Git 待推送提交同步到远端"
                self._record_result("成功", summary, protocol=protocol, target=plan["target_display"])
                return summary
            summary = f"{self._protocol_label(protocol)}已是最新状态"
            self._record_result("无变更", summary, protocol=protocol, target=plan["target_display"])
            return summary

        summary = f"推送 {pushed} 篇 · 拉取 {pulled} 篇 · 冲突 {conflict_count} 篇"
        if asset_count > 0:
            summary += f" · 附件 {asset_count} 个"
        self._record_result("成功", summary, protocol=protocol, target=plan["target_display"], pushed=pushed, pulled=pulled, conflicts=conflict_count, assets=asset_count)
        return f"已完成{self._protocol_label(protocol)}同步：{summary}"

    # ---------- Dispatch & UI ----------

    def _build_pending_confirm(self, plan, reasons):
        sample_lines = (
            [f"[覆盖本地] {p}" for p in plan["to_pull_overwrite"]]
            + [f"[覆盖远端] {p}" for p in plan["to_push_overwrite"]]
            + [f"[冲突副本] {p} -> {cr}" for p, cr, _ in plan["conflicts"]]
            + [f"[拉取] {p}" for p in plan["to_pull_new"]]
            + [f"[推送] {p}" for p in plan["to_push_new"]]
            + [f"[远端缺失] {p}" for p in plan["remote_missing"]]
            + [f"[本地缺失] {p}" for p in plan["local_missing"]]
        )
        return {
            "nb_key": self._notebook_key(),
            "fingerprint": plan["fingerprint"],
            "protocol": plan["protocol"],
            "target_display": plan["target_display"],
            "reasons": list(reasons),
            "badge": f"需确认 · {len(reasons)} 项风险",
            "sample_lines": sample_lines,
        }

    def _run_sync(self, bridge, only_path=None, confirmed=False, approved_plan=None):
        protocol = self.config.get("protocol", "local_mirror")
        if approved_plan is not None:
            plan = approved_plan
            protocol = plan.get("protocol", protocol)
        else:
            try:
                plan = self._compute_sync_plan(bridge, self.config, only_path=only_path, inspect_remote=True, force_refresh=True)
            except Exception as exc:
                msg = f"{self._protocol_label(protocol)}同步未完成: {sanitize_error_text(exc)}"
                self._append_log(f"{self._protocol_label(protocol)}同步", msg)
                self._record_result("失败", msg, protocol=protocol)
                self._save_runtime(bridge)
                self.last_status = msg
                raise RuntimeError(msg) from exc

        if plan.get("remote_error"):
            msg = plan["remote_error"]
            self._append_log(f"{self._protocol_label(protocol)}同步", msg)
            self._record_result("失败", msg, protocol=protocol, target=plan["target_display"])
            self._save_runtime(bridge)
            self.last_status = msg
            raise RuntimeError(msg)

        if not confirmed:
            reasons = self._assess_dangerous_changes(plan, self.config)
            if reasons:
                if only_path is not None:
                    msg = f"自动同步暂停（{reasons[0]}），请手动确认"
                    self._append_log(only_path, msg)
                    self._record_result("待确认", msg, protocol=protocol, target=plan["target_display"])
                    self._save_runtime(bridge)
                    self.last_status = msg
                    return msg
                self.pending_confirm = self._build_pending_confirm(plan, reasons)
                msg = "检测到危险变更，请先确认后执行"
                self._append_log("等待危险变更确认", reasons[0])
                self._record_result("待确认", reasons[0], protocol=protocol, target=plan["target_display"])
                self._save_runtime(bridge)
                self.last_status = msg
                return msg

        try:
            msg = self._execute_sync_plan(bridge, plan, only_path=only_path)
        except Exception as exc:
            msg = sanitize_error_text(exc)
            if not msg.startswith(self._protocol_label(protocol)) and "Git" not in msg:
                msg = f"{self._protocol_label(protocol)}同步未完成: {msg}"
            self._append_log(f"{self._protocol_label(protocol)}同步", msg)
            self._record_result("失败", msg, protocol=protocol, target=plan["target_display"])
            self._save_runtime(bridge)
            self.last_status = msg
            raise RuntimeError(msg) from exc

        self._save_runtime(bridge)
        self.last_status = msg
        return msg

    def _run_test_conn(self):
        protocol = self.config.get("protocol", "local_mirror")
        if protocol == "webdav":
            ok, msg = self._test_webdav()
        elif protocol == "git":
            ok, msg = self._test_git()
        else:
            ok, msg = self._test_local_mirror()
        self._append_log(f"测试连接 ({self._protocol_label(protocol)})", "通过" if ok else "未连通")
        self.last_status = msg
        return msg

    def _conflict_policy_label(self, policy):
        return {
            "keep_both": "保留双份副本",
            "remote_first": "远端优先",
            "local_first": "本地优先",
        }.get(policy, "保留双份副本")

    def _build_preview_items(self, bridge, cfg):
        if self.pending_confirm and self.pending_confirm.get("nb_key") == self._notebook_key():
            pc = self.pending_confirm
            lines = [f"[风险] {r}" for r in pc.get("reasons", [])]
            samples = pc.get("sample_lines") or []
            max_samples = max(1, 9 - len(lines))
            lines.extend(samples[:max_samples])
            if len(samples) > max_samples:
                lines.append(f"... 其余 {len(samples) - max_samples} 项变更")
            return [
                {
                    "kind": "preview",
                    "preview": {
                        "variant": "plan",
                        "palette": "warm",
                        "title": f"危险变更确认 · {self._protocol_label(pc.get('protocol'))}",
                        "badge": pc.get("badge", "需确认"),
                        "subtitle": f"目标：{pc.get('target_display', '')}",
                        "body": "\n".join(lines[:10]),
                    },
                },
                {
                    "kind": "actions",
                    "buttons": [
                        {"id": "confirm_sync", "label": "确认执行同步", "variant": "danger"},
                        {"id": "cancel_confirm", "label": "取消", "variant": "secondary"},
                    ],
                },
            ]

        protocol = cfg.get("protocol", "local_mirror")
        mode_label = self._protocol_label(protocol)
        scope = cfg.get("sync_scope", "all")
        scope_desc = "全部笔记" if scope == "all" else f"仅 {scope}/ 目录"
        policy_desc = f"冲突策略：{self._conflict_policy_label(cfg.get('conflict_policy'))}"

        plan = self._compute_sync_plan(bridge, cfg, inspect_remote=(protocol == "local_mirror"))
        prefix_title = "首次同步预览" if plan["is_first_sync"] else "同步计划预览"
        subtitle = f"目标：{plan['target_display']}"

        if not plan["remote_inspected"]:
            local_count = len(plan["local_notes"])
            if plan.get("remote_error"):
                badge = f"未就绪 · 本地 {local_count} 篇"
                lines = [f"[提示] {plan['remote_error']}"]
            else:
                badge = f"{'首次同步 · ' if plan['is_first_sync'] else ''}待检查远端 · 本地 {local_count} 篇"
                local_keys = sorted(plan["local_notes"].keys())
                lines = [f"[待检查] {p}" for p in local_keys[:6]] if local_keys else ["当前范围暂无本地笔记（0 篇）"]
                if len(local_keys) > 6:
                    lines.append(f"... 其余 {len(local_keys) - 6} 篇笔记")
            lines.append(f"同步范围：{scope_desc} | {policy_desc}")
        else:
            n_push = len(plan["to_push_new"]) + len(plan["to_push_overwrite"])
            n_pull = len(plan["to_pull_new"]) + len(plan["to_pull_overwrite"])
            n_conf = len(plan["conflicts"])
            badge = f"{'首次 · ' if plan['is_first_sync'] else ''}推送 {n_push} · 拉取 {n_pull}"
            if n_conf:
                badge += f" · 冲突 {n_conf}"
            entries = (
                [f"[推送] {p}" for p in plan["to_push_new"]]
                + [f"[覆盖远端] {p}" for p in plan["to_push_overwrite"]]
                + [f"[拉取] {p}" for p in plan["to_pull_new"]]
                + [f"[覆盖本地] {p}" for p in plan["to_pull_overwrite"]]
                + [f"[冲突] {p}" for p, _, _ in plan["conflicts"]]
                + [f"[已同步] {p}" for p in plan["synced"]]
            )
            if not entries:
                lines = ["当前范围暂无笔记（0 篇），目标已就绪"]
            else:
                lines = entries[:6]
                if len(entries) > 6:
                    lines.append(f"... 其余 {len(entries) - 6} 篇笔记")
            dangers = self._assess_dangerous_changes(plan, cfg)
            if dangers:
                lines.append(f"[需确认] {dangers[0]}")
            lines.append(f"同步范围：{scope_desc} | {policy_desc}")

        return [
            {
                "kind": "preview",
                "preview": {
                    "variant": "plan",
                    "palette": "ocean",
                    "title": f"{prefix_title} · {mode_label}",
                    "badge": badge,
                    "subtitle": subtitle,
                    "body": "\n".join(lines[:10]),
                },
            },
            {
                "kind": "actions",
                "buttons": [
                    {"id": "refresh_preview", "label": "刷新预览", "variant": "secondary"},
                ],
            },
        ]

    def build_page(self, bridge, cfg=None):
        c = cfg or self.config
        protocol = c.get("protocol", "local_mirror")
        mode_label = self._protocol_label(protocol)
        total_synced = int(self.stats.get("total_synced", 0) or 0)
        last_sync = self.stats.get("last_sync") or "尚未同步"
        entries = [self._normalize_log(item) for item in self.logs[:MAX_LOG_ENTRIES]]

        local_paths = self._list_local_note_paths(bridge)
        top_dirs = self._extract_top_dirs(local_paths)
        scope_options = [{"value": "all", "label": "整个笔记本"}] + [
            {"value": d, "label": f"子目录 · {d}/"} for d in top_dirs
        ]
        valid_scopes = {opt["value"] for opt in scope_options}
        scope_val = c.get("sync_scope", "all")
        if scope_val not in valid_scopes:
            scope_val = "all"

        nb_label = self._notebook_label()
        nb_path_display = self._notebook_key() if self.notebook_root else "未指定笔记本目录"
        target_items = [
            {
                "kind": "kv",
                "rows": [
                    {"label": "当前笔记本", "value": f"{nb_label} ({nb_path_display})"},
                ],
            },
            {
                "kind": "segmented",
                "id": "protocol",
                "label": "存储协议",
                "value": protocol,
                "options": [
                    {"value": "local_mirror", "label": "目录镜像"},
                    {"value": "webdav", "label": "WebDAV"},
                    {"value": "git", "label": "Git 仓库"},
                ],
            },
            {
                "kind": "select",
                "id": "mirror_preset",
                "label": "镜像目录预设",
                "value": c.get("mirror_preset", "downloads"),
                "options": [
                    {"value": "downloads", "label": "下载目录 · ~/Downloads/Block-Sync"},
                    {"value": "documents", "label": "文稿目录 · ~/Documents/Block-Sync"},
                    {"value": "custom", "label": "自定义文件夹…"},
                ],
                "visible_when": {"control_id": "protocol", "equals": "local_mirror"},
            },
        ]
        if protocol == "local_mirror":
            target_items.append({
                "kind": "folder",
                "id": "mirror_dir",
                "label": "自定义镜像文件夹",
                "value": c.get("mirror_dir", ""),
                "placeholder": "选择本地备份目录",
                "visible_when": {"control_id": "mirror_preset", "equals": "custom"},
            })

        target_items.extend([
            {
                "kind": "input",
                "id": "webdav_url",
                "label": "WebDAV 服务器地址",
                "value": c.get("webdav_url", ""),
                "placeholder": "例如 https://dav.example.com/dav",
                "visible_when": {"control_id": "protocol", "equals": "webdav"},
            },
            {
                "kind": "select",
                "id": "webdav_dir_preset",
                "label": "远端目录预设",
                "value": c.get("webdav_dir_preset", "/BlockNotes"),
                "options": [
                    {"value": "/BlockNotes", "label": "/BlockNotes"},
                    {"value": "/Notes", "label": "/Notes"},
                    {"value": "/Markdown", "label": "/Markdown"},
                    {"value": "custom", "label": "自定义路径…"},
                ],
                "visible_when": {"control_id": "protocol", "equals": "webdav"},
            },
        ])
        if protocol == "webdav":
            target_items.append({
                "kind": "input",
                "id": "webdav_dir",
                "label": "自定义远端目录",
                "value": c.get("webdav_dir", "/BlockNotes"),
                "placeholder": "/BlockNotes",
                "visible_when": {"control_id": "webdav_dir_preset", "equals": "custom"},
            })

        target_items.extend([
            {
                "kind": "input",
                "id": "webdav_user",
                "label": "账号用户名",
                "value": c.get("webdav_user", ""),
                "placeholder": "WebDAV 登录用户名",
                "visible_when": {"control_id": "protocol", "equals": "webdav"},
            },
            {
                "kind": "secret",
                "id": "webdav_pass",
                "label": "应用密码",
                "value": c.get("webdav_pass", ""),
                "placeholder": "WebDAV 应用专用密码或访问令牌",
                "visible_when": {"control_id": "protocol", "equals": "webdav"},
            },
            {
                "kind": "input",
                "id": "git_remote",
                "label": "Git 远端仓库地址",
                "value": c.get("git_remote", ""),
                "placeholder": "例如 git@github.com:user/notes.git 或 https://...",
                "visible_when": {"control_id": "protocol", "equals": "git"},
            },
            {
                "kind": "segmented",
                "id": "git_branch_preset",
                "label": "分支名称",
                "value": c.get("git_branch_preset", "main"),
                "options": [
                    {"value": "main", "label": "main"},
                    {"value": "master", "label": "master"},
                    {"value": "custom", "label": "自定义"},
                ],
                "visible_when": {"control_id": "protocol", "equals": "git"},
            },
        ])
        if protocol == "git":
            target_items.append({
                "kind": "input",
                "id": "git_branch",
                "label": "自定义分支名称",
                "value": c.get("git_branch", "main"),
                "placeholder": "main",
                "visible_when": {"control_id": "git_branch_preset", "equals": "custom"},
            })

        target_items.extend([
            {
                "kind": "segmented",
                "id": "git_auth",
                "label": "Git 认证方式",
                "value": c.get("git_auth", "ssh"),
                "options": [
                    {"value": "ssh", "label": "本机 SSH 密钥"},
                    {"value": "token", "label": "HTTPS 令牌"},
                ],
                "visible_when": {"control_id": "protocol", "equals": "git"},
            },
            {
                "kind": "secret",
                "id": "git_token",
                "label": "访问令牌",
                "value": c.get("git_token", ""),
                "placeholder": "HTTPS 令牌认证时填写，使用本机 SSH 密钥时可留空",
                "visible_when": {"control_id": "protocol", "equals": "git"},
            },
        ])

        action_buttons = [
            {"id": "save_config", "label": "保存配置", "variant": "primary"},
            {"id": "test_conn", "label": "测试连接", "variant": "secondary"},
        ]
        if protocol == "local_mirror":
            action_buttons.append({"id": "reveal_mirror", "label": "在访达中打开备份目录", "variant": "secondary"})
        target_items.append({"kind": "actions", "buttons": action_buttons})

        preview_items = self._build_preview_items(bridge, c)
        last_res = self._get_last_result() or {}
        last_attempt_status = last_res.get("status") or "尚未尝试"
        last_attempt_time = last_res.get("time") or "尚未尝试"
        last_attempt_target = last_res.get("target") or self._target_display(c)
        last_attempt_summary = last_res.get("summary") or "暂无最近尝试记录"

        last_ok = last_res.get("last_success") if isinstance(last_res.get("last_success"), dict) else None
        if not last_ok and last_res.get("status") in ("成功", "无变更"):
            last_ok = last_res
        last_success_time = (last_ok or {}).get("time") or (last_sync if last_sync != "尚未同步" else "尚未成功")
        if last_ok:
            last_success_detail = f"{last_ok.get('time', '')} · {last_ok.get('summary', '')} ({last_ok.get('target', '')})"
        else:
            last_success_detail = "暂无成功同步记录"

        return {
            "title": "同步",
            "status": self.last_status or f"{mode_label} · 已就绪",
            "header_actions": [
                {"id": "sync_now", "label": "立即同步", "variant": "primary"},
            ],
            "cards": [
                {
                    "id": "target-card",
                    "title": "存储目标（当前笔记本）",
                    "items": target_items,
                },
                {
                    "id": "preview-card",
                    "title": "同步计划预览",
                    "items": preview_items,
                },
                {
                    "id": "policy-card",
                    "title": "同步范围与安全保护",
                    "items": [
                        {
                            "kind": "select",
                            "id": "sync_scope",
                            "label": "同步范围",
                            "value": scope_val,
                            "options": scope_options,
                        },
                        {
                            "kind": "switch",
                            "id": "auto_sync",
                            "label": "保存笔记后自动同步",
                            "value": bool(c.get("auto_sync", True)),
                        },
                        {
                            "kind": "segmented",
                            "id": "sync_interval",
                            "label": "定时同步周期",
                            "value": c.get("sync_interval", "manual"),
                            "options": [
                                {"value": "manual", "label": "仅手动"},
                                {"value": "5m", "label": "每 5 分钟"},
                                {"value": "30m", "label": "每 30 分钟"},
                            ],
                        },
                        {
                            "kind": "switch",
                            "id": "sync_assets",
                            "label": "同步 assets 图片附件",
                            "value": bool(c.get("sync_assets", True)),
                        },
                        {
                            "kind": "segmented",
                            "id": "conflict_policy",
                            "label": "冲突处理策略",
                            "value": c.get("conflict_policy", "keep_both"),
                            "options": [
                                {"value": "keep_both", "label": "保留双份副本"},
                                {"value": "remote_first", "label": "远端优先"},
                                {"value": "local_first", "label": "本地优先"},
                            ],
                        },
                        {
                            "kind": "switch",
                            "id": "delete_guard",
                            "label": "远端批量删除保护（超 5 篇暂停）",
                            "value": bool(c.get("delete_guard", True)),
                        },
                    ],
                },
                {
                    "id": "status-card",
                    "title": "同步概览与最近结果",
                    "items": [
                        {
                            "kind": "metrics",
                            "metrics": [
                                {"label": "当前模式", "value": mode_label},
                                {"label": "累计同步篇数", "value": f"{total_synced} 篇"},
                                {"label": "最近成功时间", "value": last_success_time},
                                {"label": "最近尝试结果", "value": last_attempt_status},
                            ],
                        },
                        {
                            "kind": "kv",
                            "rows": [
                                {"label": "最近尝试时间", "value": last_attempt_time},
                                {"label": "最近尝试目标", "value": last_attempt_target},
                                {"label": "最近尝试详情", "value": last_attempt_summary},
                                {"label": "最近成功详情", "value": last_success_detail},
                            ],
                        },
                        {
                            "kind": "log_list",
                            "empty_text": "暂无同步记录",
                            "entries": entries,
                        },
                    ],
                },
            ],
        }

    def handle(self, bridge, method, params):
        if method == "plugin.initialize":
            self.plugin_id = str(params.get("plugin_id") or "block-sync")
            self.data_dir = str(params.get("data_dir") or "")
            dl = str(params.get("downloads_dir") or "").strip()
            self.downloads_dir = dl or os.path.expanduser("~/Downloads")
            self.notebook_root = str(params.get("notebook_root") or "")
            self.locale = str(params.get("locale") or "zh")
            self._load_state(bridge)
            return {"ready": True}

        if method == "plugin.render":
            values = params.get("values")
            if isinstance(values, dict) and values:
                cfg = self._normalize_config(values, base=self.config)
            else:
                cfg = dict(self.config)
            return {"page": self.build_page(bridge, cfg=cfg)}

        if method == "plugin.action":
            values = params.get("values") or {}
            action_id = str(params.get("action_id") or "")
            if isinstance(values, dict) and values:
                next_cfg = self._normalize_config(values)
                if next_cfg != self.config and action_id not in ("confirm_sync", "cancel_confirm"):
                    self.pending_confirm = None
                    self._remote_preview_cache.clear()
                self.config = next_cfg
                self._save_config(bridge)

            extra = {}
            if action_id == "save_config":
                self._save_config(bridge)
                self._append_log("保存配置", f"{self._notebook_label()} · {self._protocol_label(self.config['protocol'])}")
                self._save_runtime(bridge)
                self.last_status = "配置已保存"
                status = "配置已保存"
            elif action_id == "test_conn":
                status = self._run_test_conn()
                self._save_runtime(bridge)
            elif action_id == "refresh_preview":
                self.pending_confirm = None
                plan = self._compute_sync_plan(bridge, self.config, inspect_remote=True, force_refresh=True)
                if plan.get("remote_error"):
                    status = plan["remote_error"]
                else:
                    n_push = len(plan["to_push_new"]) + len(plan["to_push_overwrite"])
                    n_pull = len(plan["to_pull_new"]) + len(plan["to_pull_overwrite"])
                    n_conf = len(plan["conflicts"])
                    status = f"预览已刷新：推送 {n_push} · 拉取 {n_pull} · 冲突 {n_conf}"
                self.last_status = status
            elif action_id == "reveal_mirror":
                mirror_dir = self._resolve_mirror_dir()
                os.makedirs(mirror_dir, exist_ok=True)
                status = f"已在访达中打开备份目录: {mirror_dir}"
                self.last_status = status
                extra["reveal_path"] = mirror_dir
            elif action_id == "sync_now":
                status = self._run_sync(bridge)
            elif action_id == "confirm_sync":
                pc = self.pending_confirm
                if not pc or pc.get("nb_key") != self._notebook_key():
                    status = "当前没有待确认的同步计划"
                    self.last_status = status
                else:
                    protocol = self.config.get("protocol", "local_mirror")
                    try:
                        plan = self._compute_sync_plan(bridge, self.config, inspect_remote=True, force_refresh=True)
                    except Exception as exc:
                        msg = f"{self._protocol_label(protocol)}同步未完成: {sanitize_error_text(exc)}"
                        self._append_log(f"{self._protocol_label(protocol)}同步", msg)
                        self._record_result("失败", msg, protocol=protocol)
                        self._save_runtime(bridge)
                        self.last_status = msg
                        raise RuntimeError(msg) from exc

                    if plan.get("remote_error"):
                        msg = plan["remote_error"]
                        self._append_log(f"{self._protocol_label(plan['protocol'])}同步", msg)
                        self._record_result("失败", msg, protocol=plan["protocol"], target=plan["target_display"])
                        self._save_runtime(bridge)
                        self.last_status = msg
                        raise RuntimeError(msg)

                    if plan["fingerprint"] != pc.get("fingerprint"):
                        reasons = self._assess_dangerous_changes(plan, self.config)
                        if reasons:
                            self.pending_confirm = self._build_pending_confirm(plan, reasons)
                            self._append_log("同步计划已变化", reasons[0])
                            self._record_result("待确认", "同步计划已变化，请重新确认", protocol=plan["protocol"], target=plan["target_display"])
                            self._save_runtime(bridge)
                            status = "同步计划已变化，请重新确认"
                            self.last_status = status
                        else:
                            self.pending_confirm = None
                            self._append_log("同步计划已变化", "原危险变更已消除，请重新同步")
                            self._record_result("待确认", "同步计划已变化，请重新同步", protocol=plan["protocol"], target=plan["target_display"])
                            self._save_runtime(bridge)
                            status = "同步计划已变化，请重新同步"
                            self.last_status = status
                    else:
                        self.pending_confirm = None
                        status = self._run_sync(bridge, confirmed=True, approved_plan=plan)
            elif action_id == "cancel_confirm":
                self.pending_confirm = None
                self._append_log("取消危险同步", "用户已取消")
                self._record_result("已取消", "用户已取消危险变更")
                self._save_runtime(bridge)
                status = "已取消本次同步"
                self.last_status = status
            else:
                status = "已完成操作"
                self.last_status = status

            res = {
                "values": dict(self.config),
                "page": self.build_page(bridge, cfg=self.config),
                "status": status,
            }
            res.update(extra)
            return res

        if method == "plugin.event":
            event_name = str(params.get("event") or "")
            rel_path = str(params.get("path") or "").replace("\\", "/")
            if event_name == "note.saved" and self.config.get("auto_sync"):
                only_path = rel_path if is_safe_rel_md(rel_path) else None
                if only_path and not self._matches_scope(only_path):
                    return {"handled": True}
                self._run_sync(bridge, only_path=only_path)
            return {"handled": True}

        if method == "plugin.shutdown":
            return {"ok": True}

        raise RuntimeError(f"unsupported method: {method}")


def main():
    plugin = SyncPlugin()
    HostBridge().serve(plugin.handle)


if __name__ == "__main__":
    main()
