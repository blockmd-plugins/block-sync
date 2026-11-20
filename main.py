#!/usr/bin/env python3
"""Official block-sync plugin for Block (blockmd)."""

import base64
from contextlib import contextmanager
import ctypes
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
    "已更新": "Updated",
    "待确认": "Confirmation Required",
    "失败": "Failed",
    "未连通": "Connection Failed",
    "已取消": "Canceled",
    "冲突副本": "Conflict Copy",
}
LAYOUTS_META_KEY = "notebook_layouts"
INITIALIZED_META_KEY = "initialized_targets"
MAX_STORED_CONFIRM_SAMPLES = 30
MAX_WEBDAV_DIRS = 2000

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


def split_markdown_code_segments(text):
    """Split Markdown text into alternating (is_code, segment) chunks.

    Recognizes CommonMark fenced code blocks (top-level, inside blockquotes, and inside list items),
    4-space/tab indented code blocks, and inline/multi-line backtick code spans (respecting
    backslash-escaped opening backticks and whitespace-only paragraph separators).
    """
    if not text:
        return []

    def expand_indent_cols(s):
        cols = 0
        for ch in s:
            if ch == " ":
                cols += 1
            elif ch == "\t":
                cols += 4 - (cols % 4)
            else:
                break
        return cols

    def split_inline_code_spans(chunk):
        out = []
        n = len(chunk)
        i = 0
        plain_start = 0
        para_sep_re = re.compile(r"\r?\n[ \t]*\r?\n")
        while i < n:
            if chunk[i] == "`":
                bs = 0
                p = i - 1
                while p >= 0 and chunk[p] == "\\":
                    bs += 1
                    p -= 1
                if bs % 2 == 1:
                    i += 1
                    continue
                j = i
                while j < n and chunk[j] == "`":
                    j += 1
                ticks = j - i
                sep_m = para_sep_re.search(chunk, j)
                limit = sep_m.start() if sep_m else n
                k = j
                matched_end = -1
                while k < limit:
                    if chunk[k] == "`":
                        m = k
                        while m < limit and chunk[m] == "`":
                            m += 1
                        if m - k == ticks:
                            matched_end = m
                            break
                        k = m
                    else:
                        k += 1
                if matched_end != -1:
                    if i > plain_start:
                        out.append((False, chunk[plain_start:i]))
                    out.append((True, chunk[i:matched_end]))
                    i = matched_end
                    plain_start = matched_end
                    continue
                i = j
            else:
                i += 1
        if plain_start < n:
            out.append((False, chunk[plain_start:]))
        return out

    bq_one_re = re.compile(r"^ {0,3}>[ \t]?(.*)$")
    list_one_re = re.compile(r"^( {0,3}(?:[*+-]|\d{1,9}[.)])(?:[ \t]+|$))(.*)$")
    fence_re = re.compile(r"^([ \t]*)(\x60{3,}|~{3,})(.*)$")
    atx_heading_re = re.compile(r"^ {0,3}#{1,6}(?:[ \t]|$)")
    thematic_break_re = re.compile(r"^ {0,3}(?:(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$")

    def strip_containers(line_body, active_indent=0):
        """Strip arbitrarily nested blockquote (`>`) and list-item (`-`/`1.`) prefixes in order.

        Returns (rest, bq_count, total_list_indent, opened_list).
        Also handles continuation indentation inside active list items before an inner `>` (e.g. `1. > ~~~` followed by `   > code`).
        """
        rest = line_body
        bq_count = 0
        total_indent = 0
        opened_list = False
        while True:
            bm = bq_one_re.match(rest)
            if bm:
                bq_count += 1
                rest = bm.group(1)
                continue
            lm = list_one_re.match(rest)
            if lm:
                marker_str = lm.group(1)
                step = expand_indent_cols(marker_str)
                if not marker_str.endswith((" ", "\t")):
                    step += 1
                total_indent += step
                rest = lm.group(2)
                opened_list = True
                continue
            # Handle continuation indentation before an inner blockquote inside a list item (e.g. "   > code").
            if active_indent > total_indent and expand_indent_cols(rest) >= (active_indent - total_indent):
                needed = active_indent - total_indent
                cols = 0
                idx = 0
                while idx < len(rest) and cols < needed:
                    if rest[idx] == " ":
                        cols += 1
                    elif rest[idx] == "\t":
                        cols += 4 - (cols % 4)
                    else:
                        break
                    idx += 1
                candidate = rest[idx:]
                bm2 = bq_one_re.match(candidate)
                if bm2:
                    total_indent = active_indent
                    bq_count += 1
                    rest = bm2.group(1)
                    continue
            break
        return rest, bq_count, total_indent, opened_list

    block_segments = []
    buf = []
    fence_char = ""
    fence_len = 0
    fence_bq_depth = 0
    fence_min_indent = 0
    in_indented_code = False
    indented_bq_depth = 0
    indented_min_cols = 4
    prev_line_blank = True
    active_list_indent = 0
    active_list_bq_depth = 0
    last_plain_sig = None

    def flush_plain():
        nonlocal buf
        if buf:
            block_segments.append((False, "".join(buf)))
            buf = []

    for raw_line in text.splitlines(keepends=True):
        body = raw_line.rstrip("\r\n")

        if fence_char:
            # Strip container prefixes matching the fence's nesting (supporting both "> ```" and "1. > ```").
            f_rest, f_bq, f_list_ind, _ = strip_containers(body, active_indent=fence_min_indent)
            f_blank = (f_rest.strip() == "")
            f_lead = expand_indent_cols(f_rest)
            effective_indent = f_list_ind + f_lead
            dropped_container = (f_bq < fence_bq_depth) or (
                not f_blank and fence_min_indent > 0 and effective_indent < fence_min_indent
            )
            if dropped_container:
                block_segments.append((True, "".join(buf)))
                buf = []
                fence_char = ""
                fence_len = 0
                fence_bq_depth = 0
                fence_min_indent = 0
                prev_line_blank = False
                last_plain_sig = None
            else:
                close_m = re.match(r"^([ \t]*)(\x60{3,}|~{3,})[ \t]*$", f_rest)
                buf.append(raw_line)
                if (
                    f_bq == fence_bq_depth
                    and close_m
                    and (f_list_ind + expand_indent_cols(close_m.group(1))) <= fence_min_indent + 3
                    and close_m.group(2)[0] == fence_char
                    and len(close_m.group(2)) >= fence_len
                ):
                    block_segments.append((True, "".join(buf)))
                    buf = []
                    fence_char = ""
                    fence_len = 0
                    fence_bq_depth = 0
                    fence_min_indent = 0
                    prev_line_blank = False
                    last_plain_sig = None
                continue

        rest, cur_depth, line_list_indent, opened_list_on_line = strip_containers(
            body, active_indent=active_list_indent,
        )
        is_blank = (rest.strip() == "")
        indent_cols = expand_indent_cols(rest)
        eff_indent = line_list_indent + indent_cols

        if in_indented_code:
            if cur_depth == indented_bq_depth and (is_blank or eff_indent >= indented_min_cols):
                buf.append(raw_line)
                prev_line_blank = is_blank
                continue
            block_segments.append((True, "".join(buf)))
            buf = []
            in_indented_code = False
            last_plain_sig = None

        if not is_blank and not opened_list_on_line and (cur_depth != active_list_bq_depth or eff_indent < active_list_indent):
            active_list_indent = 0
            active_list_bq_depth = 0

        if opened_list_on_line:
            active_list_indent = line_list_indent
            active_list_bq_depth = cur_depth

        # Check fenced code block opening (top-level, in blockquote, in list, or in list+blockquote).
        fence_base_indent = line_list_indent if opened_list_on_line else (active_list_indent if cur_depth == active_list_bq_depth else 0)
        max_fence_lead = 3 if (opened_list_on_line or line_list_indent >= fence_base_indent) else (fence_base_indent + 3)
        fm = fence_re.match(rest)
        if fm and expand_indent_cols(fm.group(1)) <= max_fence_lead:
            ch = fm.group(2)[0]
            info = fm.group(3)
            if ch != "`" or "`" not in info:
                flush_plain()
                fence_char = ch
                fence_len = len(fm.group(2))
                fence_bq_depth = cur_depth
                fence_min_indent = fence_base_indent
                buf.append(raw_line)
                prev_line_blank = False
                last_plain_sig = None
                continue

        # Indented code block (CommonMark §4.4: 4 cols beyond container indent, not interrupting paragraph).
        min_indented_cols = (active_list_indent + 4) if (cur_depth == active_list_bq_depth and active_list_indent > 0) else 4
        if prev_line_blank and not is_blank and not opened_list_on_line and eff_indent >= min_indented_cols:
            flush_plain()
            in_indented_code = True
            indented_bq_depth = cur_depth
            indented_min_cols = min_indented_cols
            buf.append(raw_line)
            prev_line_blank = False
            last_plain_sig = None
            continue

        # Block boundaries: ATX headings, thematic breaks, blank lines, and container changes must NOT
        # share inline backtick code spans across leaf blocks (CommonMark §6.1).
        is_leaf_boundary = bool(atx_heading_re.match(rest) or thematic_break_re.match(rest))
        cur_sig = (cur_depth, active_list_indent if cur_depth == active_list_bq_depth else 0)
        if is_blank or is_leaf_boundary or opened_list_on_line or (last_plain_sig is not None and cur_sig != last_plain_sig):
            flush_plain()
        buf.append(raw_line)
        if is_blank or is_leaf_boundary:
            flush_plain()
            last_plain_sig = None
        else:
            last_plain_sig = cur_sig
        prev_line_blank = is_blank

    if buf:
        block_segments.append((bool(fence_char or in_indented_code), "".join(buf)))

    final_segments = []
    for is_code, seg in block_segments:
        if is_code:
            final_segments.append((True, seg))
        else:
            final_segments.extend(split_inline_code_spans(seg))
    return final_segments


def note_asset_paths(note_path, text):
    # Block emits Markdown links/images and HTML src attributes for resized media.
    # Reuse the exact same CommonMark code scanner as rewrite_note_asset_links.
    visible_parts = []
    for is_code, seg in split_markdown_code_segments(text):
        if is_code:
            # Preserve line breaks so line-anchored reference-link regexes keep accurate boundaries.
            visible_parts.append(re.sub(r"[^\r\n]", " ", seg))
        else:
            visible_parts.append(seg)
    visible_text = "".join(visible_parts)
    bare_dest = r"(?:\\.|[^\s()<>\\]|\((?:\\.|[^\s()<>\\])*\))+"
    link_dest = rf"<([^>\n]+)>|({bare_dest})"
    links = re.findall(rf"\]\(\s*(?:{link_dest})(?=[\s)])", visible_text)
    refs = re.findall(
        rf"(?m)^(?: {{0,3}}>[ \t]?)* {{0,3}}\[(?:\\.|[^\]\\\n])+\]:[ \t]*(?:\r?\n(?: {{0,3}}>[ \t]?)*[ \t]*)?(?:{link_dest})(?=[ \t\r]|$)",
        visible_text,
    )
    attrs = re.findall(r"""(?is)\b(?:src|href)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""", visible_text)
    note_dir = posixpath.dirname(note_path)
    paths = set()
    for dest in (*links, *refs, *attrs):
        value = html.unescape(next(part for part in dest if part))
        value = re.sub(r"\\([()<>\\])", r"\1", value)
        decoded = urllib.parse.unquote(value.split("#", 1)[0].split("?", 1)[0])
        for candidate in {value, decoded}:
            if candidate.startswith(("/", "\\")) or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", candidate):
                continue
            rel_path = posixpath.normpath(posixpath.join(note_dir, candidate))
            if is_safe_rel_asset(rel_path):
                paths.add(rel_path)
    return paths


def make_conflict_path(rel_path, tag):
    norm = rel_path.replace("\\", "/")
    stem, extension = os.path.splitext(norm)
    return f"{stem}.conflict-{tag}{extension or '.md'}"


def atomic_swap_files(path_a, path_b):
    """Atomically exchange two existing paths on macOS via renamex_np(RENAME_SWAP).

    Returns True on success, False if the platform/filesystem does not support atomic swap.
    """
    if sys.platform != "darwin":
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        fn = libc.renamex_np
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
    except Exception:
        return False
    rc = fn(os.fsencode(path_a), os.fsencode(path_b), 0x00000002)
    if rc == 0:
        return True
    err = ctypes.get_errno()
    if err in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EXDEV, errno.EINVAL):
        return False
    raise OSError(err, os.strerror(err), path_b)


def atomic_swap_files_at(dir_fd, name_a, name_b):
    """Atomically exchange two existing entries within an open directory fd on macOS via renameatx_np(RENAME_SWAP).

    Returns True on success, False if the platform/filesystem does not support atomic swap.
    """
    if sys.platform != "darwin":
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        fn = libc.renameatx_np
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
    except Exception:
        return False
    rc = fn(int(dir_fd), os.fsencode(name_a), int(dir_fd), os.fsencode(name_b), 0x00000002)
    if rc == 0:
        return True
    err = ctypes.get_errno()
    if err in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EXDEV, errno.EINVAL):
        return False
    raise OSError(err, os.strerror(err), name_b)


def make_unique_conflict_path(
    rel_path,
    remote_text,
    existing_local=None,
    existing_remote=None,
    reserved=None,
    check_local=None,
    check_remote=None,
):
    """Choose a deterministic content-based conflict path that never collides across retries or same-second saves."""
    norm = rel_path.replace("\\", "/")
    stem, extension = os.path.splitext(norm)
    ext = extension or ".md"
    fingerprint = sha256_text(remote_text)[:8]
    local_map = existing_local or {}
    remote_map = existing_remote or {}
    used = reserved if reserved is not None else set()
    attempt = 1
    while True:
        suffix = "" if attempt == 1 else f"-{attempt}"
        candidate = f"{stem}.conflict-{fingerprint}{suffix}{ext}"
        if candidate not in used:
            loc_cur = local_map.get(candidate)
            if loc_cur is None and check_local is not None:
                loc_cur = check_local(candidate)
            rem_cur = remote_map.get(candidate)
            if rem_cur is None and check_remote is not None:
                rem_cur = check_remote(candidate)
            if loc_cur in (None, remote_text) and rem_cur in (None, remote_text):
                used.add(candidate)
                return candidate
        attempt += 1


def rewrite_note_asset_links(note_path, text, asset_copy_map):
    """Rewrite relative references in a remote-adopted note so it opens the remote conflict asset copies.

    Preserves fenced code blocks and inline code spans verbatim.
    """
    if not asset_copy_map or not text:
        return text
    note_dir = posixpath.dirname(note_path.replace("\\", "/"))

    def resolve_replacement(raw_dest):
        if not raw_dest:
            return None
        unesc = html.unescape(raw_dest)
        unesc = re.sub(r"\\([()<>\\])", r"\1", unesc)
        base_part, sep_q, rest_q = unesc.partition("?")
        base_part, sep_h, rest_h = base_part.partition("#")
        tail = (sep_h + rest_h) + (sep_q + rest_q)
        decoded = urllib.parse.unquote(base_part)
        for cand in (base_part, decoded):
            if not cand or cand.startswith(("/", "\\")) or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", cand):
                continue
            rel = posixpath.normpath(posixpath.join(note_dir, cand))
            if rel in asset_copy_map:
                target_rel = asset_copy_map[rel]
                rel_from_note = posixpath.relpath(target_rel, note_dir) if note_dir else target_rel
                if base_part.startswith("./") and not rel_from_note.startswith("."):
                    rel_from_note = "./" + rel_from_note
                if base_part != decoded and "%" in base_part:
                    rel_from_note = "/".join(urllib.parse.quote(seg, safe="") for seg in rel_from_note.split("/"))
                return rel_from_note + tail
        return None

    def encode_md_bare_dest(dest_str):
        out = dest_str.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").replace("<", "\\<").replace(">", "\\>")
        if re.search(r"\s", out):
            return f"<{dest_str.replace('<', '%3C').replace('>', '%3E')}>"
        return out

    def encode_md_angle_dest(dest_str):
        return dest_str.replace("\\", "\\\\").replace("<", "\\<").replace(">", "\\>")

    bare_dest = r"(?:\\.|[^\s()<>\\]|\((?:\\.|[^\s()<>\\])*\))+"

    def repl_md(match):
        prefix, angle, bare = match.group(1), match.group(2), match.group(3)
        raw = angle if angle is not None else bare
        updated = resolve_replacement(raw)
        if not updated:
            return match.group(0)
        if angle is not None:
            return f"{prefix}<{encode_md_angle_dest(updated)}>"
        return f"{prefix}{encode_md_bare_dest(updated)}"

    def repl_attr(match):
        prefix, q1, q2, bare = match.group(1), match.group(2), match.group(3), match.group(4)
        raw = q1 if q1 is not None else (q2 if q2 is not None else bare)
        updated = resolve_replacement(raw)
        if not updated:
            return match.group(0)
        if q1 is not None:
            return f'{prefix}"{html.escape(updated, quote=True)}"'
        if q2 is not None:
            return f"{prefix}'{html.escape(updated, quote=True)}'"
        return f"{prefix}{updated}"

    def rewrite_plain_segment(segment):
        out = re.sub(rf"(\]\(\s*)(?:<([^>\n]+)>|({bare_dest}))(?=[\s)])", repl_md, segment)
        out = re.sub(
            rf"(?m)^((?:(?: {{0,3}}>[ \t]?)* {{0,3}})\[(?:\\.|[^\]\\\n])+\]:[ \t]*(?:\r?\n(?: {{0,3}}>[ \t]?)*[ \t]*)?)(?:<([^>\n]+)>|({bare_dest}))(?=[ \t\r]|$)",
            repl_md,
            out,
        )
        out = re.sub(r"""(?is)(\b(?:src|href)\s*=\s*)(?:"([^"]+)"|'([^']+)'|([^\s>]+))""", repl_attr, out)
        return out

    out_parts = []
    for is_code, seg in split_markdown_code_segments(text):
        out_parts.append(seg if is_code else rewrite_plain_segment(seg))
    return "".join(out_parts)


def safe_parse_url(raw):
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return urllib.parse.urlparse(text)
    except ValueError:
        return None


def has_embedded_url_credentials(raw, allow_ssh_username=True):
    parsed = safe_parse_url(raw)
    if parsed is None or not parsed.scheme:
        return False
    scheme = parsed.scheme.lower()
    if scheme in ("http", "https"):
        return parsed.username is not None or parsed.password is not None
    if scheme == "ssh":
        if parsed.password is not None:
            return True
        if not allow_ssh_username and parsed.username is not None:
            return True
    return False


def sanitize_url_for_display(raw):
    text = str(raw or "").strip()
    if not text:
        return ""
    parsed = safe_parse_url(text)
    if parsed is None or parsed.scheme.lower() not in ("http", "https", "ssh"):
        return text
    if parsed.username is None and parsed.password is None:
        return text
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    if parsed.scheme.lower() == "ssh" and parsed.username and parsed.password is None:
        netloc = f"{parsed.username}@{netloc}"
    return urllib.parse.urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def normalize_http_url(raw):
    parsed = safe_parse_url(raw)
    if parsed is None or parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    raw_path = parsed.path or "/"
    encoded_segments = []
    for seg in raw_path.split("/"):
        if not seg:
            encoded_segments.append("")
        else:
            encoded_segments.append(urllib.parse.quote(urllib.parse.unquote(seg), safe="-._~:@!$&'()*+,;="))
    norm_path = "/".join(encoded_segments)
    if not norm_path.startswith("/"):
        norm_path = "/" + norm_path
    norm_path = norm_path.rstrip("/") + "/"
    return urllib.parse.urlunparse((parsed.scheme.lower(), netloc, norm_path, "", "", ""))


def paths_overlap(path_a, path_b):
    """Detect ancestor/descendant/identity overlap including symlinks and case-insensitive volumes."""
    if not path_a or not path_b:
        return False
    a = os.path.realpath(path_a)
    b = os.path.realpath(path_b)
    try:
        if os.path.commonpath((a, b)) in (a, b):
            return True
    except ValueError:
        return False
    # Walk existing parent chains using os.path.samefile to catch case-insensitive macOS/Windows aliases.
    def existing_chain(p):
        chain = []
        cur = p
        while cur:
            if os.path.exists(cur):
                chain.append(cur)
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        return chain

    if os.path.exists(a):
        for anc in existing_chain(b):
            try:
                if os.path.samefile(a, anc):
                    return True
            except OSError:
                pass
    if os.path.exists(b):
        for anc in existing_chain(a):
            try:
                if os.path.samefile(b, anc):
                    return True
            except OSError:
                pass
    return False


def sanitize_error_text(exc):
    msg = str(exc).strip().replace("\n", " ")
    # Strip embedded credentials from any http(s)/ssh URLs before logging or surfacing errors.
    msg = re.sub(r"((?:https?|ssh)://)([^/\s@]+)@", r"\1***@", msg, flags=re.IGNORECASE)
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
        self.pending_confirms = {}
        self._remote_preview_cache = {}
        self.kv_tooltip = False
        self.supports_checklist = False
        self.supports_form_layout = False
        self.supports_multi_notebook = False
        self.last_status = ""
        self._last_synced_notebooks = []

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
        host_listed = False
        if self.supports_multi_notebook and bridge is not None:
            try:
                res = bridge.call_host("host.notebooks.list", {})
                if isinstance(res, dict) and isinstance(res.get("notebooks"), list):
                    host_listed = True
                    for item in res["notebooks"]:
                        if isinstance(item, dict):
                            p = item.get("path")
                            add_entry(
                                p,
                                item.get("name"),
                                bool(item.get("active")) or (active_norm and self._norm_nb_path(p) == active_norm),
                            )
            except Exception:
                pass

        if not host_listed:
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
        if not self.supports_multi_notebook:
            if nb_key in self.notebook_configs:
                self.config = self._normalize_config(self.notebook_configs[nb_key], base=DEFAULT_CONFIG)
            elif raw_cfg is not None and not raw_cfg.get("selected_notebooks"):
                self.config = self._normalize_config(raw_cfg, base=DEFAULT_CONFIG)
            else:
                self.config = dict(DEFAULT_CONFIG)
            if self.notebook_root:
                self.config["selected_notebooks"] = [self._norm_nb_path(self.notebook_root)]
        elif raw_cfg is not None and "selected_notebooks" in raw_cfg:
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

        self.pending_confirms = {}
        pcs_res = bridge.call_host("host.storage.get", {"key": "pending_confirms"})
        if pcs_res.get("found") and isinstance(pcs_res.get("value"), dict):
            for k, v in pcs_res["value"].items():
                norm = self._normalize_pending_confirm(v)
                if norm:
                    self.pending_confirms[str(k)] = norm
        pc_res = bridge.call_host("host.storage.get", {"key": "pending_confirm"})
        if pc_res.get("found"):
            legacy_pc = self._normalize_pending_confirm(pc_res.get("value"))
            if legacy_pc and legacy_pc["scope_key"] not in self.pending_confirms:
                self.pending_confirms[legacy_pc["scope_key"]] = legacy_pc
        self.pending_confirm = self.pending_confirms.get(self._result_key())
        self._remote_preview_cache = {}
        self.last_status = ""

    def _normalize_pending_confirm(self, raw):
        if not isinstance(raw, dict):
            return None
        scope_key = str(raw.get("scope_key") or "").strip()
        fingerprint = str(raw.get("fingerprint") or "").strip()
        protocol = str(raw.get("protocol") or "").strip()
        reasons = [str(r).strip() for r in (raw.get("reasons") or []) if str(r or "").strip()]
        reason_items = [r for r in (raw.get("reason_items") or []) if isinstance(r, dict) and r.get("kind")]
        if not scope_key or not fingerprint or protocol not in VALID_PROTOCOLS or (not reasons and not reason_items):
            return None
        sample_items = [s for s in (raw.get("sample_items") or []) if isinstance(s, dict) and s.get("kind") and s.get("path")][:MAX_STORED_CONFIRM_SAMPLES]
        sample_lines = [str(s).strip() for s in (raw.get("sample_lines") or []) if str(s or "").strip()][:MAX_STORED_CONFIRM_SAMPLES]
        total_samples = int(raw.get("total_samples") or len(sample_items) or len(sample_lines) or 0)
        return {
            "scope_key": scope_key,
            "fingerprint": fingerprint,
            "protocol": protocol,
            "target_display": sanitize_url_for_display(raw.get("target_display") or ""),
            "reasons": reasons[:30],
            "reason_items": reason_items[:30],
            "badge": str(raw.get("badge") or "").strip(),
            "sample_items": sample_items,
            "sample_lines": sample_lines,
            "total_samples": total_samples,
        }

    def _set_pending_confirm(self, pending, bridge=None):
        norm = self._normalize_pending_confirm(pending) if pending else None
        key = self._result_key()
        self.pending_confirm = norm
        if norm is None:
            self.pending_confirms.pop(key, None)
        else:
            self.pending_confirms[key] = norm
        if bridge is not None:
            bridge.call_host("host.storage.set", {"key": "pending_confirms", "value": self.pending_confirms})
            bridge.call_host("host.storage.set", {"key": "pending_confirm", "value": self.pending_confirm})

    def _clear_pending_confirm(self, bridge=None):
        key = self._result_key()
        had = self.pending_confirm is not None or key in self.pending_confirms
        self.pending_confirm = None
        self.pending_confirms.pop(key, None)
        if had and bridge is not None:
            bridge.call_host("host.storage.set", {"key": "pending_confirms", "value": self.pending_confirms})
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
        if isinstance(entry.get("log_key"), str) and entry.get("log_key"):
            item["log_key"] = entry["log_key"]
            if isinstance(entry.get("log_args"), dict):
                item["log_args"] = dict(entry["log_args"])
        return item

    def _render_structured_log(self, key, args):
        a = args or {}
        path = str(a.get("path") or "")
        proto = self._protocol_label(a.get("protocol") or "local_mirror")
        if key == "push_new":
            return self._tr(f"推送 {path}", f"Push {path}"), self._tr(f"已推送到{proto}", f"Pushed to {proto}")
        if key == "push_update":
            return self._tr(f"更新 {path}", f"Update {path}"), self._tr(f"已同步修改到{proto}", f"Synced changes to {proto}")
        if key == "push_overwrite":
            return self._tr(f"本地覆盖 {path}", f"Overwrite remote: {path}"), self._tr(f"本地优先覆盖{proto}", f"Local version took precedence on {proto}")
        if key == "pull_new":
            return self._tr(f"拉取 {path}", f"Pull {path}"), self._tr(f"已从{proto}拉取", f"Pulled from {proto}")
        if key == "pull_update":
            return self._tr(f"拉取更新 {path}", f"Pull update: {path}"), self._tr(f"已从{proto}拉取更新", f"Pulled update from {proto}")
        if key == "pull_overwrite":
            return self._tr(f"远端覆盖 {path}", f"Overwrite local: {path}"), self._tr(f"{proto}优先更新本地", f"Version from {proto} replaced the local copy")
        if key == "conflict_copy":
            copy_rel = str(a.get("copy") or "")
            return self._tr(f"冲突保留 {path}", f"Keep conflict copy: {path}"), self._tr(f"已保留副本 {copy_rel}", f"Saved a copy at {copy_rel}")
        if key == "assets_synced":
            prefix = str(a.get("prefix") or "")
            count = int(a.get("count") or 0)
            return self._tr(f"{prefix}同步 {count} 个附件", f"{prefix}Synced attachments: {count}"), ""
        if key == "test_conn":
            return self._tr(f"测试连接 ({proto})", f"Test connection ({proto})"), ""
        if key == "sync_noop":
            return self._tr(f"{proto}同步", f"{proto} sync"), self._tr(f"{proto}已是最新状态", f"{proto} is up to date")
        if key == "sync_canceled":
            return self._tr("危险变更同步", "Sync with risky changes"), self._tr("用户已取消本次同步", "The user canceled this sync")
        if key == "plan_changed":
            return self._tr("同步计划已变化", "The sync plan changed"), self._tr("原危险变更已消除，请重新同步", "The original risks are gone. Start sync again.")
        if key == "auto_paused":
            return self._tr(f"自动同步暂停 ({path})", f"Auto-sync paused ({path})"), ""
        if key == "confirm_required" and isinstance(a.get("reason_item"), dict):
            return self._format_reason_item(a["reason_item"]), self._tr("检测到危险变更，请先确认后执行", "Risky changes detected. Confirm to continue.")
        return None, None

    def _log_for_page(self, entry):
        item = self._normalize_log(entry)
        log_key = item.pop("log_key", None)
        log_args = item.pop("log_args", None)
        recorded_in_english = item.pop("locale", None) == "en"
        if log_key:
            loc_title, loc_tip = self._render_structured_log(log_key, log_args)
            if loc_title:
                item["title"] = loc_title
            if loc_tip:
                item["tooltip"] = loc_tip
        if not self._is_en():
            return item

        status = item["status"]
        status = LOG_STATUS_EN.get(status, status)
        item["status"] = "Complete" if CHINESE_TEXT.search(status) else status
        # Legacy entries without structured keys: translate common prefixes while preserving note filenames.
        if not log_key and not recorded_in_english:
            if CHINESE_TEXT.search(item["title"]):
                for zh_pfx, en_pfx in (
                    ("推送 ", "Push "),
                    ("更新 ", "Update "),
                    ("本地覆盖 ", "Overwrite remote: "),
                    ("拉取更新 ", "Pull update: "),
                    ("拉取 ", "Pull "),
                    ("远端覆盖 ", "Overwrite local: "),
                    ("冲突保留 ", "Keep conflict copy: "),
                ):
                    if item["title"].startswith(zh_pfx):
                        item["title"] = en_pfx + item["title"][len(zh_pfx):]
                        break
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
        if self.supports_multi_notebook:
            bridge.call_host("host.storage.set", {"key": "config", "value": self.config})

    def _save_runtime(self, bridge):
        key = self._result_key()
        if self.pending_confirm is None:
            self.pending_confirms.pop(key, None)
        else:
            self.pending_confirms[key] = self.pending_confirm
        bridge.call_host("host.storage.set", {"key": "stats", "value": self.stats})
        bridge.call_host("host.storage.set", {"key": "logs", "value": self.logs[:MAX_LOG_ENTRIES]})
        bridge.call_host("host.storage.set", {"key": "sync_meta", "value": self.sync_meta})
        bridge.call_host("host.storage.set", {"key": "notebook_results", "value": self.notebook_results})
        bridge.call_host("host.storage.set", {"key": "pending_confirms", "value": self.pending_confirms})
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
            return sanitize_url_for_display(self._webdav_base_url(c)) or self._tr("未配置 WebDAV 地址", "WebDAV address is missing")
        target = sanitize_url_for_display(c.get("git_remote") or "")
        branch = self._git_branch(c)
        repo_dir = self._resolve_local_git_dir(c)
        return f"{target} ({branch})" if target else f"{repo_dir} ({branch})"

    def _append_log(self, title, status, tone="", tooltip="", log_key=None, log_args=None):
        raw = {
            "title": str(title or self._tr("同步任务", "Sync task")).strip() or self._tr("同步任务", "Sync task"),
            "status": str(status or "成功").strip() or "成功",
            "time": now_hms(),
            "tone": tone,
            "tooltip": tooltip,
        }
        if log_key:
            raw["log_key"] = log_key
            raw["log_args"] = dict(log_args or {})
        entry = self._normalize_log(raw)
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
        for idx_nb, nb in enumerate(selected):
            for prev_nb in selected[:idx_nb]:
                if paths_overlap(prev_nb, nb):
                    return self._tr(
                        f"笔记本「{self._notebook_label(prev_nb)}」与「{self._notebook_label(nb)}」的本地目录重叠，请取消其中一个",
                        f"Local folders for {self._notebook_label(prev_nb)} and {self._notebook_label(nb)} overlap; deselect one",
                    )
        roots_to_check = selected if selected else ([self.notebook_root] if self.notebook_root else [])
        protocol = cfg["protocol"]
        if protocol == "webdav":
            raw_url = str(cfg.get("webdav_url") or "").strip()
            if raw_url and has_embedded_url_credentials(raw_url, allow_ssh_username=False):
                return self._tr(
                    "请不要在 WebDAV 地址中内嵌账号密码，改用下方认证字段填写",
                    "Do not embed credentials in the WebDAV URL; use the username and password fields instead",
                )
            if not self._webdav_base_url(cfg):
                return self._tr("请填写有效的 WebDAV 地址", "Enter a valid WebDAV address")
        elif protocol == "git":
            raw_remote = str(cfg.get("git_remote") or "").strip()
            if not raw_remote:
                return self._tr("请填写 Git 仓库地址", "Enter a Git repository address")
            if self._is_remote_git_url(raw_remote):
                if has_embedded_url_credentials(raw_remote, allow_ssh_username=True):
                    return self._tr(
                        "请不要在 Git 仓库地址中内嵌账号或令牌，改用下方认证方式填写",
                        "Do not embed credentials in the Git URL; use the authentication fields instead",
                    )
                if raw_remote.lower().startswith(("http://", "https://")) and not normalize_http_url(raw_remote):
                    return self._tr("请填写有效的 Git HTTP(S) 仓库地址", "Enter a valid Git HTTP(S) repository URL")
            else:
                local_git = self._resolve_local_git_dir(cfg)
                for nb in roots_to_check:
                    if paths_overlap(nb, local_git):
                        return self._tr(
                            f"Git 本地仓库目录不能与笔记本「{self._notebook_label(nb)}」重叠",
                            f"The local Git folder cannot overlap with notebook {self._notebook_label(nb)}",
                        )
        elif protocol == "local_mirror":
            target = self._resolve_mirror_dir(cfg)
            if not target:
                return self._tr("请先选择同步文件夹", "Select a sync folder first")
            for nb in roots_to_check:
                if paths_overlap(nb, target):
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
        if only_path is not None:
            if not is_safe_rel_md(only_path) or is_safe_rel_asset(only_path):
                return notes
            params = {"path": only_path}
            if nb_root and self.supports_multi_notebook:
                params["notebook_root"] = nb_root
            try:
                res = bridge.call_host("host.notes.read", params)
                if isinstance(res, dict) and res.get("found") is not False and "content" in res:
                    notes[only_path] = str(res.get("content") or "")
            except RuntimeError as exc:
                low = str(exc).lower()
                if any(tok in low for tok in ("not found", "no such file", "does not exist", "missing")):
                    return notes
                raise
            return notes
        all_paths = paths if paths is not None else self._list_local_note_paths(bridge, nb_root=nb_root)
        for rel_path in all_paths:
            if not is_safe_rel_md(rel_path):
                continue
            if not self._matches_scope(rel_path, scope):
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

    def _excluded_real_dirs(self, root_dir, excluded_subdirs):
        if not excluded_subdirs or not root_dir:
            return []
        root_real = os.path.realpath(root_dir)
        ex_keys = {sync_dir_key(d) for d in excluded_subdirs if d}
        if not ex_keys:
            return []
        reals = set()
        if os.path.isdir(root_real):
            try:
                for entry in os.listdir(root_real):
                    if sync_dir_key(entry) in ex_keys:
                        reals.add(os.path.realpath(os.path.join(root_real, entry)))
            except OSError:
                pass
        for key in ex_keys:
            reals.add(os.path.realpath(os.path.join(root_real, key)))
        return sorted(reals)

    def _path_hits_excluded(self, dest_real, excluded_reals):
        for ex_real in excluded_reals:
            if dest_real == ex_real or dest_real.startswith(ex_real + os.sep) or paths_overlap(dest_real, ex_real):
                return True
        return False

    def _asset_file(self, root_dir, rel_path, excluded_subdirs=()):
        if not is_safe_rel_asset(rel_path):
            raise ValueError(self._tr(f"无效的附件路径：{rel_path}", f"Invalid attachment path: {rel_path}"))
        root_real = os.path.realpath(root_dir)
        path = os.path.join(root_real, *rel_path.split("/"))
        dest_real = os.path.realpath(path)
        if not dest_real.startswith(root_real + os.sep):
            raise ValueError(self._tr(f"附件路径超出同步目录：{rel_path}", f"Attachment path is outside the sync folder: {rel_path}"))
        if excluded_subdirs:
            ex_reals = self._excluded_real_dirs(root_real, excluded_subdirs)
            if self._path_hits_excluded(dest_real, ex_reals):
                raise ValueError(self._tr(f"附件路径进入其他笔记本的同步目录：{rel_path}", f"Attachment path resolves into another notebook's sync folder: {rel_path}"))
        return path

    def _read_asset_file(self, root_dir, rel_path, excluded_subdirs=()):
        try:
            with open(self._asset_file(root_dir, rel_path, excluded_subdirs=excluded_subdirs), "rb") as fh:
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
        if not root_dir or not os.path.isdir(root_dir):
            return names
        root_real = os.path.realpath(root_dir)
        ex_reals = self._excluded_real_dirs(root_real, excluded_subdirs)
        for root, dirs, files in os.walk(root_dir):
            kept_dirs = []
            for d in dirs:
                if d.startswith("."):
                    continue
                if root == root_dir and sync_dir_key(d) in excluded_subdirs:
                    continue
                d_real = os.path.realpath(os.path.join(root, d))
                if not d_real.startswith(root_real + os.sep):
                    continue
                if ex_reals and self._path_hits_excluded(d_real, ex_reals):
                    continue
                kept_dirs.append(d)
            dirs[:] = kept_dirs
            for name in files:
                if name.startswith("."):
                    continue
                full = os.path.join(root, name)
                f_real = os.path.realpath(full)
                if not f_real.startswith(root_real + os.sep):
                    continue
                if ex_reals and self._path_hits_excluded(f_real, ex_reals):
                    continue
                rel = os.path.relpath(full, root_dir).replace(os.sep, "/")
                if is_safe_rel_asset(rel):
                    names.add(rel)
        return names

    def _asset_paths_for_sync(self, root_dir, paths, excluded_subdirs):
        local_paths = self._list_dir_assets(root_dir) if paths is None else paths
        for rel in local_paths:
            if in_sync_subdir(rel, excluded_subdirs):
                raise RuntimeError(self._tr(f"附件路径与其他笔记本的同步目录重叠：{rel}", f"Attachment path overlaps with another notebook's sync folder: {rel}"))
        return local_paths

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

        conflict_rel = make_unique_conflict_path(rel_path, remote_text)
        return "keep_both", local_text, (conflict_rel, remote_text), local_hash

    # ---------- Local Mirror Mode ----------

    @contextmanager
    def _target_lock(self, target_dir):
        if fcntl is None or not target_dir:
            yield
            return
        lock_root = os.path.join(self.data_dir or tempfile.gettempdir(), "locks")
        os.makedirs(lock_root, exist_ok=True)
        try:
            os.makedirs(target_dir, exist_ok=True)
            st = os.stat(target_dir)
            identity = f"dev:{st.st_dev}:ino:{st.st_ino}"
        except OSError:
            real_path = os.path.realpath(target_dir)
            identity = real_path.lower() if sys.platform in ("darwin", "win32") else real_path
        key = sha256_text(identity)[:16]
        lock_path = os.path.join(lock_root, f"{key}.lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                pass
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    def _has_git_marker(self, repo_dir):
        if not repo_dir:
            return False
        g = os.path.join(repo_dir, ".git")
        return os.path.isdir(g) or os.path.isfile(g)

    def _resolve_git_dir(self, start_dir):
        """Return (work_tree_root, actual_git_dir) if start_dir is inside a Git repo (supporting .git pointer files)."""
        cur = os.path.realpath(start_dir)
        while cur:
            git_entry = os.path.join(cur, ".git")
            if os.path.isdir(git_entry):
                return cur, os.path.realpath(git_entry)
            if os.path.isfile(git_entry):
                try:
                    with open(git_entry, "r", encoding="utf-8", errors="replace") as fh:
                        first_line = fh.readline().strip()
                    if first_line.lower().startswith("gitdir:"):
                        raw_gd = first_line.split(":", 1)[1].strip()
                        if raw_gd:
                            gd = raw_gd if os.path.isabs(raw_gd) else os.path.join(cur, raw_gd)
                            if os.path.isdir(gd):
                                return cur, os.path.realpath(gd)
                except OSError:
                    pass
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        return "", ""

    def _ensure_git_info_exclude(self, wt_root, git_dir, pattern):
        try:
            exclude_path = ""
            if wt_root and shutil.which("git"):
                proc = subprocess.run(
                    ["git", "rev-parse", "--git-path", "info/exclude"],
                    cwd=wt_root,
                    env=self._git_env(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    raw_path = proc.stdout.strip()
                    exclude_path = raw_path if os.path.isabs(raw_path) else os.path.join(wt_root, raw_path)
            if not exclude_path:
                exclude_path = os.path.join(git_dir, "info", "exclude")
            os.makedirs(os.path.dirname(exclude_path), exist_ok=True)
            existing = ""
            if os.path.isfile(exclude_path):
                with open(exclude_path, "r", encoding="utf-8", errors="replace") as fh:
                    existing = fh.read()
            lines = [ln.strip() for ln in existing.splitlines()]
            if pattern not in lines:
                with open(exclude_path, "a", encoding="utf-8") as fh:
                    if existing and not existing.endswith("\n"):
                        fh.write("\n")
                    fh.write(f"{pattern}\n")
        except OSError:
            pass

    def _stash_replaced_inode(self, temp_path, root_dir, rel_path):
        """Move a swapped-out inode into a bounded same-volume recovery dir without unlinking it.

        Preserves the exact inode so an external editor holding an open fd that flushes in-place
        writes after RENAME_SWAP still lands safely on disk. If the primary recovery directory is
        blocked (e.g. a regular file named .block-sync-replaced exists), falls back to a dot-prefixed
        recovery file beside temp_path that does not end with .tmp (avoiding stale temp cleanup).
        """
        if not temp_path or not os.path.exists(temp_path):
            return ""
        root_real = os.path.realpath(root_dir)
        now_ms = int(time.time() * 1000)
        base_name = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.basename(rel_path))[:48] or "file"
        tag = f"{now_ms:015d}-{sha256_text(rel_path)[:8]}-{base_name}"

        try:
            root_dev = os.stat(root_real).st_dev
        except OSError:
            root_dev = None

        candidate_dirs = []
        wt_root, git_dir = self._resolve_git_dir(root_real)
        if git_dir:
            try:
                if root_dev is None or os.stat(git_dir).st_dev == root_dev:
                    candidate_dirs.append((os.path.join(git_dir, "block-sync-replaced"), False, ""))
            except OSError:
                pass
            stash_wt = wt_root or root_real
            candidate_dirs.append((os.path.join(stash_wt, ".block-sync-replaced"), True, "/.block-sync-replaced/"))
            candidate_dirs.append((os.path.join(stash_wt, ".block-sync-recovery"), True, "/.block-sync-recovery/"))
        else:
            candidate_dirs.append((os.path.join(root_real, ".block-sync-replaced"), False, ""))
            candidate_dirs.append((os.path.join(root_real, ".block-sync-recovery"), False, ""))

        for stash_dir, needs_exclude, excl_pat in candidate_dirs:
            try:
                if os.path.exists(stash_dir) and not os.path.isdir(stash_dir):
                    continue
                os.makedirs(stash_dir, exist_ok=True)
                if needs_exclude and git_dir and excl_pat:
                    self._ensure_git_info_exclude(wt_root, git_dir, excl_pat)
                dest_stash = os.path.join(stash_dir, tag)
                for idx in range(50):
                    cand = dest_stash if idx == 0 else f"{dest_stash}-{idx}"
                    if not os.path.exists(cand):
                        os.replace(temp_path, cand)
                        # Prune oldest entries beyond 64 by stash-entry timestamp prefix, never pruning
                        # the freshly stashed inode or entries stashed within the last 60 seconds.
                        try:
                            cutoff_ms = now_ms - 60000
                            names = sorted(os.listdir(stash_dir))
                            cand_name = os.path.basename(cand)
                            if len(names) > 64:
                                for old_name in names[:-64]:
                                    if old_name == cand_name:
                                        continue
                                    ts_part = old_name.split("-", 1)[0]
                                    if ts_part.isdigit() and int(ts_part) >= cutoff_ms:
                                        continue
                                    try:
                                        os.unlink(os.path.join(stash_dir, old_name))
                                    except OSError:
                                        pass
                        except OSError:
                            pass
                        return cand
            except OSError:
                continue

        # Final same-directory fallback: rename temp_path to a dot-prefixed recovery filename that does NOT
        # end with ".tmp" so _cleanup_stale_temp_files will never delete it.
        fallback_dir = os.path.dirname(temp_path) or root_real
        for idx in range(50):
            fb = os.path.join(fallback_dir, f".block-sync-keep-{tag}" + ("" if idx == 0 else f"-{idx}"))
            if not os.path.exists(fb):
                try:
                    os.replace(temp_path, fb)
                    if git_dir:
                        self._ensure_git_info_exclude(wt_root, git_dir, ".block-sync-keep-*")
                    return fb
                except OSError:
                    break
        return temp_path

    def _preserve_external_temp(self, temp_path, dest, hash_hex, default_ext=""):
        stem, ext = os.path.splitext(dest)
        use_ext = ext or default_ext
        short = str(hash_hex or "unknown")[:8]
        for idx in range(100):
            suffix = "" if idx == 0 else f"-{idx}"
            candidate = f"{stem}.conflict-external-{short}{suffix}{use_ext}"
            try:
                os.link(temp_path, candidate)
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
                return candidate
            except FileExistsError:
                continue
            except OSError as err:
                if err.errno not in (
                    errno.EXDEV,
                    errno.ENOTSUP,
                    errno.EOPNOTSUPP,
                    errno.ENOSYS,
                    errno.EMLINK,
                ):
                    return ""
                if os.path.exists(candidate):
                    continue
                try:
                    os.replace(temp_path, candidate)
                    return candidate
                except OSError:
                    return ""
        return ""

    def _safe_mirror_dest(self, mirror_dir, rel_path, excluded_subdirs=()):
        if not is_safe_rel_path(rel_path):
            raise ValueError(self._tr(f"无效的笔记路径：{rel_path}", f"Invalid note path: {rel_path}"))
        root_real = os.path.realpath(mirror_dir)
        dest = os.path.join(root_real, *rel_path.split("/"))
        dest_real = os.path.realpath(dest)
        if not dest_real.startswith(root_real + os.sep):
            raise ValueError(self._tr(f"文件路径超出同步目录：{rel_path}", f"File path is outside the sync folder: {rel_path}"))
        if excluded_subdirs:
            ex_reals = self._excluded_real_dirs(root_real, excluded_subdirs)
            if self._path_hits_excluded(dest_real, ex_reals):
                raise ValueError(self._tr(f"文件路径进入其他笔记本的同步目录：{rel_path}", f"File path resolves into another notebook's sync folder: {rel_path}"))
        return dest

    def _test_local_mirror(self):
        mirror_dir = self._resolve_mirror_dir()
        probe_file = None
        try:
            os.makedirs(mirror_dir, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=mirror_dir,
                prefix=".block-sync-probe-",
                suffix=".tmp",
                delete=False,
            ) as fh:
                probe_file = fh.name
                fh.write("ok")
            return True, self._tr(f"目录镜像可用: {mirror_dir}", f"Local mirror is available: {mirror_dir}")
        except Exception as exc:
            return False, self._tr(f"目录镜像不可写: {self._error_detail(exc)}", f"Local mirror is not writable: {self._error_detail(exc)}")
        finally:
            if probe_file:
                try:
                    os.unlink(probe_file)
                except OSError:
                    pass

    def _decode_note_bytes(self, raw_bytes, rel_path):
        try:
            return raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(self._tr(
                f"笔记 {rel_path} 不是有效的 UTF-8 编码，为避免损坏内容已中止同步",
                f"Note {rel_path} is not valid UTF-8; sync aborted to avoid corrupting content",
            )) from exc

    def _resolve_actual_rel_casing(self, base_dir, rel_path):
        """Return the true on-disk casing of rel_path relative to base_dir on case-insensitive disks."""
        parts = [p for p in rel_path.replace("\\", "/").split("/") if p]
        cur_dir = base_dir
        resolved_parts = []
        for part in parts:
            try:
                entries = os.listdir(cur_dir)
            except OSError:
                return rel_path
            if part in entries:
                chosen = part
            else:
                target_cf = part.casefold()
                chosen = None
                cand_full = os.path.join(cur_dir, part)
                for entry in entries:
                    if entry.casefold() == target_cf:
                        try:
                            if os.path.samefile(os.path.join(cur_dir, entry), cand_full):
                                chosen = entry
                                break
                        except OSError:
                            pass
                if chosen is None:
                    return rel_path
            resolved_parts.append(chosen)
            cur_dir = os.path.join(cur_dir, chosen)
        return "/".join(resolved_parts)

    def _scan_mirror_files(self, mirror_dir, only_path=None, scope=None, excluded_subdirs=()):
        remote_files = {}
        if not os.path.isdir(mirror_dir):
            return remote_files
        root_real = os.path.realpath(mirror_dir)
        ex_reals = self._excluded_real_dirs(root_real, excluded_subdirs)
        if only_path:
            if is_safe_rel_asset(only_path) or in_sync_subdir(only_path, excluded_subdirs):
                return remote_files
            try:
                candidate = self._safe_mirror_dest(mirror_dir, only_path, excluded_subdirs=excluded_subdirs)
            except ValueError:
                return remote_files
            if os.path.isfile(candidate):
                actual_rel = self._resolve_actual_rel_casing(mirror_dir, only_path)
                with open(candidate, "rb") as fh:
                    remote_files[actual_rel] = self._decode_note_bytes(fh.read(), actual_rel)
            return remote_files

        for root, dirs, files in os.walk(mirror_dir):
            kept_dirs = []
            for d in dirs:
                if d.startswith(".") or d == "assets":
                    continue
                if root == mirror_dir and sync_dir_key(d) in excluded_subdirs:
                    continue
                d_real = os.path.realpath(os.path.join(root, d))
                if not d_real.startswith(root_real + os.sep):
                    continue
                if ex_reals and self._path_hits_excluded(d_real, ex_reals):
                    continue
                kept_dirs.append(d)
            dirs[:] = kept_dirs
            for name in files:
                if name.startswith("."):
                    continue
                full = os.path.join(root, name)
                f_real = os.path.realpath(full)
                if not f_real.startswith(root_real + os.sep):
                    continue
                if ex_reals and self._path_hits_excluded(f_real, ex_reals):
                    continue
                rel = os.path.relpath(full, mirror_dir).replace(os.sep, "/")
                if not is_safe_rel_md(rel) or in_sync_subdir(rel, excluded_subdirs) or not self._matches_scope(rel, scope):
                    continue
                with open(full, "rb") as fh:
                    remote_files[rel] = self._decode_note_bytes(fh.read(), rel)
        return remote_files

    def _open_verified_dir_fd(self, target_dir, expected_real=None, expected_real_stat=None, disallow_symlink=False):
        if os.name == "nt":
            return None
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if disallow_symlink:
            flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target_dir, flags)
        try:
            st = os.fstat(fd)
            if expected_real_stat is not None and (st.st_dev, st.st_ino) != expected_real_stat:
                raise RuntimeError(self._tr(
                    f"同步目标目录已被替换，已中止写入：{target_dir}",
                    f"Sync target directory was replaced; write aborted: {target_dir}",
                ))
            if expected_real is not None and os.path.realpath(target_dir) != expected_real:
                raise RuntimeError(self._tr(
                    f"同步目标目录路径已变更，已中止写入：{target_dir}",
                    f"Sync target directory path changed; write aborted: {target_dir}",
                ))
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _walk_dir_fd(self, root_fd, rel_parts, create_missing=False):
        """Walk rel_parts strictly via open directory fds with O_NOFOLLOW; caller owns returned fd if != root_fd."""
        cur_fd = root_fd
        owned = False
        o_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            for part in rel_parts:
                try:
                    nxt = os.open(part, o_dir, dir_fd=cur_fd)
                except FileNotFoundError:
                    if not create_missing:
                        raise
                    try:
                        os.mkdir(part, 0o755, dir_fd=cur_fd)
                    except FileExistsError:
                        pass
                    nxt = os.open(part, o_dir, dir_fd=cur_fd)
                if owned:
                    os.close(cur_fd)
                cur_fd = nxt
                owned = True
            return cur_fd, owned
        except BaseException:
            if owned:
                os.close(cur_fd)
            raise

    def _preserve_external_temp_at(self, parent_fd, tmp_name, base_name, hash_hex, default_ext=""):
        stem, ext = os.path.splitext(base_name)
        use_ext = ext or default_ext
        short = str(hash_hex or "unknown")[:8]
        for idx in range(100):
            suffix = "" if idx == 0 else f"-{idx}"
            candidate = f"{stem}.conflict-external-{short}{suffix}{use_ext}"
            try:
                os.link(tmp_name, candidate, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                try:
                    os.unlink(tmp_name, dir_fd=parent_fd)
                except OSError:
                    pass
                return candidate
            except FileExistsError:
                continue
            except OSError as err:
                if err.errno not in (
                    errno.EXDEV,
                    errno.ENOTSUP,
                    errno.EOPNOTSUPP,
                    errno.ENOSYS,
                    errno.EMLINK,
                ):
                    return ""
                try:
                    os.lstat(candidate, dir_fd=parent_fd)
                    continue
                except FileNotFoundError:
                    pass
                try:
                    os.replace(tmp_name, candidate, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    return candidate
                except OSError:
                    return ""
        return ""

    def _stash_candidates_for_root(self, root_dir, rel_path):
        root_real = os.path.realpath(root_dir)
        now_ms = int(time.time() * 1000)
        base_name = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.basename(rel_path))[:48] or "file"
        tag = f"{now_ms:015d}-{sha256_text(rel_path)[:8]}-{base_name}"
        try:
            root_dev = os.stat(root_real).st_dev
        except OSError:
            root_dev = None
        candidate_dirs = []
        wt_root, git_dir = self._resolve_git_dir(root_real)
        if git_dir:
            try:
                if root_dev is None or os.stat(git_dir).st_dev == root_dev:
                    candidate_dirs.append((os.path.join(git_dir, "block-sync-replaced"), False, ""))
            except OSError:
                pass
            stash_wt = wt_root or root_real
            candidate_dirs.append((os.path.join(stash_wt, ".block-sync-replaced"), True, "/.block-sync-replaced/"))
            candidate_dirs.append((os.path.join(stash_wt, ".block-sync-recovery"), True, "/.block-sync-recovery/"))
        else:
            candidate_dirs.append((os.path.join(root_real, ".block-sync-replaced"), False, ""))
            candidate_dirs.append((os.path.join(root_real, ".block-sync-recovery"), False, ""))
        return now_ms, tag, wt_root, git_dir, candidate_dirs

    def _prune_stash_dir(self, stash_dir, cand_name, now_ms):
        try:
            cutoff_ms = now_ms - 60000
            names = sorted(os.listdir(stash_dir))
            if len(names) > 64:
                for old_name in names[:-64]:
                    if old_name == cand_name:
                        continue
                    ts_part = old_name.split("-", 1)[0]
                    if ts_part.isdigit() and int(ts_part) >= cutoff_ms:
                        continue
                    try:
                        os.unlink(os.path.join(stash_dir, old_name))
                    except OSError:
                        pass
        except OSError:
            pass

    def _stash_replaced_inode_at(self, parent_fd, tmp_name, root_dir, rel_path):
        """Move a swapped-out inode from parent_fd/tmp_name into a same-volume recovery dir without unlinking."""
        now_ms, tag, wt_root, git_dir, candidate_dirs = self._stash_candidates_for_root(root_dir, rel_path)
        for stash_dir, needs_exclude, excl_pat in candidate_dirs:
            try:
                if os.path.exists(stash_dir) and not os.path.isdir(stash_dir):
                    continue
                os.makedirs(stash_dir, exist_ok=True)
                if needs_exclude and git_dir and excl_pat:
                    self._ensure_git_info_exclude(wt_root, git_dir, excl_pat)
                dest_stash = os.path.join(stash_dir, tag)
                for idx in range(50):
                    cand = dest_stash if idx == 0 else f"{dest_stash}-{idx}"
                    if not os.path.exists(cand):
                        os.replace(tmp_name, cand, src_dir_fd=parent_fd)
                        self._prune_stash_dir(stash_dir, os.path.basename(cand), now_ms)
                        return cand
            except OSError:
                continue
        # Fallback inside parent_fd with non-.tmp name so stale temp cleanup never deletes it.
        for idx in range(50):
            fb = f".block-sync-keep-{tag}" + ("" if idx == 0 else f"-{idx}")
            try:
                os.lstat(fb, dir_fd=parent_fd)
                continue
            except FileNotFoundError:
                pass
            try:
                os.replace(tmp_name, fb, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                if git_dir:
                    self._ensure_git_info_exclude(wt_root, git_dir, ".block-sync-keep-*")
                return fb
            except OSError:
                break
        return tmp_name

    def _link_existing_to_stash_at(self, parent_fd, base_name, root_dir, rel_path):
        """Create a same-volume hard link to parent_fd/base_name in the recovery dir BEFORE rename on non-swap FS."""
        now_ms, tag, wt_root, git_dir, candidate_dirs = self._stash_candidates_for_root(root_dir, rel_path)
        for stash_dir, needs_exclude, excl_pat in candidate_dirs:
            try:
                if os.path.exists(stash_dir) and not os.path.isdir(stash_dir):
                    continue
                os.makedirs(stash_dir, exist_ok=True)
                if needs_exclude and git_dir and excl_pat:
                    self._ensure_git_info_exclude(wt_root, git_dir, excl_pat)
                dest_stash = os.path.join(stash_dir, tag)
                for idx in range(50):
                    cand = dest_stash if idx == 0 else f"{dest_stash}-{idx}"
                    try:
                        os.link(base_name, cand, src_dir_fd=parent_fd)
                        return cand, stash_dir, now_ms
                    except FileExistsError:
                        continue
            except OSError:
                continue
        return "", "", now_ms

    def _read_all_at(self, parent_fd, name):
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            chunks = []
            while True:
                buf = os.read(fd, 65536)
                if not buf:
                    break
                chunks.append(buf)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _same_inode_at(self, parent_fd, name, want_stat):
        if want_stat is None or not name:
            return False
        try:
            st = os.lstat(name, dir_fd=parent_fd)
            return st.st_dev == want_stat.st_dev and st.st_ino == want_stat.st_ino
        except OSError:
            return False

    def _write_mirror_payload(
        self,
        mirror_dir,
        rel_path,
        raw_bytes,
        is_text=False,
        expected_hash=None,
        create_only=False,
        excluded_subdirs=(),
        verify_target=None,
        root_dir_fd=None,
        change_err="",
    ):
        if verify_target is not None:
            verify_target()
        if is_text:
            dest = self._safe_mirror_dest(mirror_dir, rel_path, excluded_subdirs=excluded_subdirs)
            content_hash = sha256_bytes(raw_bytes)
            default_ext = ".md"
        else:
            dest = self._asset_file(mirror_dir, rel_path, excluded_subdirs=excluded_subdirs)
            content_hash = sha256_bytes(raw_bytes)
            default_ext = ""

        def hash_bytes(b):
            return sha256_bytes(b)

        parts = rel_path.split("/")
        dir_parts = parts[:-1]
        base_name = parts[-1]
        pid = os.getpid()

        # POSIX dir_fd-anchored path (eliminates post-verify_target symlink swap TOCTOU).
        if os.name != "nt":
            opened_root_fd = None
            parent_fd = None
            parent_owned = False
            tmp_name = None
            our_tmp_stat = None
            try:
                if root_dir_fd is not None:
                    base_fd = root_dir_fd
                else:
                    os.makedirs(mirror_dir, exist_ok=True)
                    opened_root_fd = os.open(os.path.realpath(mirror_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    base_fd = opened_root_fd
                parent_fd, parent_owned = self._walk_dir_fd(base_fd, dir_parts, create_missing=True)
                # Create unique PID-tagged temp file directly inside parent_fd.
                for idx in range(100):
                    cand_tmp = f".block-sync-{pid}-{int(time.time() * 1000000)}-{idx}.tmp"
                    try:
                        tfd = os.open(
                            cand_tmp,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                            0o644,
                            dir_fd=parent_fd,
                        )
                        tmp_name = cand_tmp
                        break
                    except FileExistsError:
                        continue
                if tmp_name is None:
                    raise RuntimeError(self._tr("无法创建临时文件", "Cannot allocate temporary file"))
                try:
                    view = memoryview(raw_bytes)
                    written = 0
                    while written < len(view):
                        n = os.write(tfd, view[written:])
                        if n <= 0:
                            raise OSError("short write")
                        written += n
                    os.fsync(tfd)
                    our_tmp_stat = os.fstat(tfd)
                finally:
                    os.close(tfd)

                if create_only:
                    try:
                        os.link(tmp_name, base_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                        return
                    except FileExistsError:
                        if hash_bytes(self._read_all_at(parent_fd, base_name)) == content_hash:
                            return
                        raise RuntimeError(change_err)
                    except OSError as err:
                        if err.errno not in (
                            errno.EXDEV,
                            errno.ENOTSUP,
                            errno.EOPNOTSUPP,
                            errno.ENOSYS,
                            errno.EMLINK,
                        ):
                            raise
                        try:
                            excl_fd = os.open(
                                base_name,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                                0o644,
                                dir_fd=parent_fd,
                            )
                        except FileExistsError:
                            if hash_bytes(self._read_all_at(parent_fd, base_name)) == content_hash:
                                return
                            raise RuntimeError(change_err)
                        try:
                            with os.fdopen(excl_fd, "wb") as out_fh:
                                out_fh.write(raw_bytes)
                                out_fh.flush()
                                os.fsync(out_fh.fileno())
                        except BaseException:
                            try:
                                os.unlink(base_name, dir_fd=parent_fd)
                            except OSError:
                                pass
                            raise
                        return

                if expected_hash is not None:
                    try:
                        existing_fd = os.open(
                            base_name,
                            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=parent_fd,
                        )
                    except (FileNotFoundError, OSError):
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
                        cur_hash = hash_bytes(b"".join(chunks))
                        if cur_hash != expected_hash and cur_hash != content_hash:
                            raise RuntimeError(change_err)
                        try:
                            st_now = os.lstat(base_name, dir_fd=parent_fd)
                        except FileNotFoundError:
                            raise RuntimeError(change_err)
                        if (
                            st_now.st_dev != st_before.st_dev
                            or st_now.st_ino != st_before.st_ino
                            or st_now.st_size != st_before.st_size
                            or st_now.st_mtime_ns != st_before.st_mtime_ns
                        ):
                            raise RuntimeError(change_err)

                        if atomic_swap_files_at(parent_fd, tmp_name, base_name):
                            # tmp_name in parent_fd now holds the exact inode that lived at base_name.
                            try:
                                swapped_hash = hash_bytes(self._read_all_at(parent_fd, tmp_name))
                            except OSError:
                                swapped_hash = ""
                            if swapped_hash != expected_hash and swapped_hash != content_hash:
                                if atomic_swap_files_at(parent_fd, tmp_name, base_name):
                                    if not self._same_inode_at(parent_fd, tmp_name, our_tmp_stat):
                                        if atomic_swap_files_at(parent_fd, tmp_name, base_name):
                                            if not self._same_inode_at(parent_fd, tmp_name, our_tmp_stat):
                                                try:
                                                    fin_hash = hash_bytes(self._read_all_at(parent_fd, tmp_name))
                                                except OSError:
                                                    fin_hash = ""
                                                self._preserve_external_temp_at(parent_fd, tmp_name, base_name, fin_hash, default_ext=default_ext)
                                                tmp_name = None
                                        else:
                                            try:
                                                rb_hash = hash_bytes(self._read_all_at(parent_fd, tmp_name))
                                            except OSError:
                                                rb_hash = ""
                                            self._preserve_external_temp_at(parent_fd, tmp_name, base_name, rb_hash, default_ext=default_ext)
                                            tmp_name = None
                                else:
                                    self._preserve_external_temp_at(parent_fd, tmp_name, base_name, swapped_hash, default_ext=default_ext)
                                    tmp_name = None
                                raise RuntimeError(change_err)
                            self._stash_replaced_inode_at(parent_fd, tmp_name, mirror_dir, rel_path)
                            tmp_name = None
                        else:
                            # Non-swap filesystem (e.g. HFS+): preserve existing inode via same-volume hard link
                            # BEFORE os.replace so an external editor holding an open fd never sees nlink drop to 0.
                            stash_path, stash_dir, now_ms = self._link_existing_to_stash_at(
                                parent_fd, base_name, mirror_dir, rel_path,
                            )
                            if not stash_path:
                                raise RuntimeError(change_err)
                            try:
                                with open(stash_path, "rb") as sfh:
                                    sbytes = sfh.read()
                                    st_stash = os.fstat(sfh.fileno())
                                if hash_bytes(sbytes) not in (expected_hash, content_hash):
                                    raise RuntimeError(change_err)
                                st_check = os.lstat(base_name, dir_fd=parent_fd)
                                if (
                                    st_check.st_dev != st_stash.st_dev
                                    or st_check.st_ino != st_stash.st_ino
                                    or st_check.st_size != st_stash.st_size
                                    or st_check.st_mtime_ns != st_stash.st_mtime_ns
                                ):
                                    raise RuntimeError(change_err)
                                os.replace(tmp_name, base_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                                tmp_name = None
                                self._prune_stash_dir(stash_dir, os.path.basename(stash_path), now_ms)
                            except BaseException:
                                try:
                                    os.unlink(stash_path)
                                except OSError:
                                    pass
                                raise
                    finally:
                        os.close(existing_fd)
                    return

                os.replace(tmp_name, base_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                tmp_name = None
                return
            finally:
                if tmp_name and parent_fd is not None and self._same_inode_at(parent_fd, tmp_name, our_tmp_stat):
                    try:
                        os.unlink(tmp_name, dir_fd=parent_fd)
                    except OSError:
                        pass
                if parent_owned and parent_fd is not None:
                    os.close(parent_fd)
                if opened_root_fd is not None:
                    os.close(opened_root_fd)

        # Windows fallback path.
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=parent or mirror_dir,
                prefix=f".block-sync-{pid}-",
                suffix=".tmp",
                delete=False,
            ) as fh:
                temp_path = fh.name
                fh.write(raw_bytes)
                fh.flush()
                os.fsync(fh.fileno())
            if create_only:
                try:
                    excl_fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                except FileExistsError:
                    with open(dest, "rb") as efh:
                        if hash_bytes(efh.read()) == content_hash:
                            return
                    raise RuntimeError(change_err)
                with os.fdopen(excl_fd, "wb") as out_fh:
                    out_fh.write(raw_bytes)
                    out_fh.flush()
                    os.fsync(out_fh.fileno())
                return
            if expected_hash is not None:
                if not os.path.exists(dest):
                    raise RuntimeError(change_err)
                with open(dest, "rb") as efh:
                    if hash_bytes(efh.read()) not in (expected_hash, content_hash):
                        raise RuntimeError(change_err)
            os.replace(temp_path, dest)
            temp_path = None
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def _write_mirror_file(
        self,
        mirror_dir,
        rel_path,
        content,
        expected_hash=None,
        create_only=False,
        excluded_subdirs=(),
        verify_target=None,
        root_dir_fd=None,
    ):
        change_err = self._tr(
            f"目标文件已变更，已中止覆盖以避免数据丢失：{rel_path}",
            f"Destination file changed during sync; aborted overwrite to protect data: {rel_path}",
        )
        self._write_mirror_payload(
            mirror_dir,
            rel_path,
            content.encode("utf-8"),
            is_text=True,
            expected_hash=expected_hash,
            create_only=create_only,
            excluded_subdirs=excluded_subdirs,
            verify_target=verify_target,
            root_dir_fd=root_dir_fd,
            change_err=change_err,
        )

    def _pid_is_alive(self, pid):
        if pid <= 0:
            return False
        if pid == os.getpid():
            return True
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False

    def _cleanup_stale_temp_files(self, root_dir, cfg=None):
        if not root_dir or not os.path.isdir(root_dir):
            return
        tracked_paths = set()
        wt_root, git_dir = self._resolve_git_dir(root_dir)
        if git_dir:
            # Read git ls-files -z in binary mode so filenames containing '\r' are preserved verbatim.
            # Supports both regular .git directories and .git pointer files (--separate-git-dir / worktrees).
            ls_proc = subprocess.run(
                ["git", "ls-files", "-z"],
                cwd=wt_root or root_dir,
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
            wt_real = os.path.realpath(wt_root or root_dir)
            root_real = os.path.realpath(root_dir)
            for raw_entry in (ls_proc.stdout or b"").split(b"\0"):
                if raw_entry:
                    full_tracked = os.path.join(wt_real, os.fsdecode(raw_entry))
                    try:
                        rel_tracked = os.path.relpath(full_tracked, root_real).replace(os.sep, "/")
                    except ValueError:
                        continue
                    if not rel_tracked.startswith("../"):
                        tracked_paths.add(rel_tracked)

        def on_walk_error(err):
            detail = f"{err.filename or root_dir} ({err})"
            raise RuntimeError(self._tr(
                f"无法扫描目录，已中止提交：{detail}",
                f"Could not scan directory; aborted commit: {detail}",
            ))

        pid_tmp_re = re.compile(r"^\.block-sync-(\d+)-.*\.tmp$")
        for cur_root, dirs, file_names in os.walk(root_dir, onerror=on_walk_error):
            # Skip .git metadata and any nested Git submodules or worktrees so their tracked files are never touched.
            dirs[:] = [
                d for d in dirs
                if d != ".git" and not os.path.exists(os.path.join(cur_root, d, ".git"))
            ]
            for name in file_names:
                if name.startswith(".block-sync-") and name.endswith(".tmp"):
                    full = os.path.join(cur_root, name)
                    rel = os.path.relpath(full, root_dir).replace(os.sep, "/")
                    if rel in tracked_paths:
                        continue
                    pm = pid_tmp_re.match(name)
                    if pm and self._pid_is_alive(int(pm.group(1))):
                        continue
                    try:
                        os.unlink(full)
                    except FileNotFoundError:
                        pass
                    except OSError as err:
                        detail = f"{rel} ({err})"
                        raise RuntimeError(self._tr(
                            f"无法清理残留临时文件，已中止提交：{detail}",
                            f"Could not clean up stale temporary files; aborted commit: {detail}",
                        ))

    def _write_mirror_bytes(
        self,
        mirror_dir,
        rel_path,
        data,
        expected_hash=None,
        create_only=False,
        excluded_subdirs=(),
        verify_target=None,
        root_dir_fd=None,
    ):
        change_err = self._tr(
            f"附件在同步期间已变更，已中止覆盖以避免数据丢失：{rel_path}",
            f"Attachment changed during sync; aborted overwrite to protect data: {rel_path}",
        )
        self._write_mirror_payload(
            mirror_dir,
            rel_path,
            data,
            is_text=False,
            expected_hash=expected_hash,
            create_only=create_only,
            excluded_subdirs=excluded_subdirs,
            verify_target=verify_target,
            root_dir_fd=root_dir_fd,
            change_err=change_err,
        )

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
        return normalize_http_url(c.get("webdav_url") or "")

    def _webdav_base_url(self, cfg=None, subdir=""):
        root = self._webdav_root_url(cfg)
        if not root:
            return ""
        sub = self._resolve_webdav_dir(cfg).strip().strip("/")
        parts = [urllib.parse.quote(p, safe="") for p in sub.split("/") if p and p not in (".", "..")] if sub else []
        if subdir:
            parts.extend(urllib.parse.quote(p, safe="") for p in subdir.strip("/").split("/") if p and p not in (".", ".."))
        if not parts:
            return root
        return root + "/".join(parts) + "/"

    def _webdav_request_full(self, method, url, body=None, extra_headers=None, timeout=6, cfg=None, retries=None):
        upper = str(method or "GET").upper()
        hdrs = self._webdav_headers(extra_headers, cfg=cfg)
        can_retry = upper in ("PROPFIND", "GET", "HEAD", "MKCOL") or (
            upper == "PUT" and any(k.lower() in ("if-match", "if-none-match") for k in hdrs)
        )
        max_retries = (2 if can_retry else 0) if retries is None else max(0, int(retries))
        for attempt in range(max_retries + 1):
            req = urllib.request.Request(
                url,
                data=body,
                headers=hdrs,
                method=upper,
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()} if resp.headers else {}
                    return resp.status, resp.read(), resp_headers
            except urllib.error.HTTPError as exc:
                if attempt < max_retries and exc.code in (429, 502, 503, 504):
                    time.sleep(min(0.4 * (attempt + 1), 1.5))
                    continue
                raise
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt < max_retries:
                    time.sleep(min(0.4 * (attempt + 1), 1.5))
                    continue
                raise

    def _webdav_request(self, method, url, body=None, extra_headers=None, timeout=6, cfg=None, retries=None):
        status, data, _ = self._webdav_request_full(
            method, url, body=body, extra_headers=extra_headers, timeout=timeout, cfg=cfg, retries=retries,
        )
        return status, data

    def _webdav_ensure_dir(self, root_url, dir_rel, cfg=None):
        parts = [p for p in dir_rel.strip("/").split("/") if p and p not in (".", "..")]
        cur = root_url
        for part in parts:
            cur = cur + urllib.parse.quote(part, safe="") + "/"
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

    def _webdav_resp_is_collection(self, resp_elem, href_text):
        dav_ns = "{DAV:}"
        saw_resourcetype = False
        for elem in list(resp_elem):
            if elem.tag not in (f"{dav_ns}propstat", "propstat"):
                continue
            status_ok = True
            prop_elem = None
            for sub in list(elem):
                if sub.tag in (f"{dav_ns}status", "status"):
                    st_txt = (sub.text or "").strip()
                    status_ok = bool(re.search(r"\b2\d\d\b", st_txt))
                elif sub.tag in (f"{dav_ns}prop", "prop"):
                    prop_elem = sub
            if not status_ok or prop_elem is None:
                continue
            for prop_child in list(prop_elem):
                if prop_child.tag in (f"{dav_ns}resourcetype", "resourcetype"):
                    saw_resourcetype = True
                    for rt_child in list(prop_child):
                        if rt_child.tag in (f"{dav_ns}collection", "collection"):
                            return True
        if saw_resourcetype:
            return False
        return href_text.endswith("/")

    def _webdav_list_files(self, base_url, filter_fn, cfg=None, timeout=6, excluded_subdirs=(), skip_assets=False):
        root_parsed = urllib.parse.urlparse(base_url)
        root_path = urllib.parse.unquote(root_parsed.path).rstrip("/") + "/"
        if not root_path.startswith("/"):
            root_path = "/" + root_path
        queue = [base_url if base_url.endswith("/") else base_url + "/"]
        visited = set()
        items = []
        max_dirs = MAX_WEBDAV_DIRS
        dav_ns = "{DAV:}"

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
            responses = [elem for elem in root.iter() if elem.tag in (f"{dav_ns}response", "response")]
            for resp in responses:
                href_text = ""
                for child in list(resp):
                    if child.tag in (f"{dav_ns}href", "href") and child.text:
                        href_text = child.text.strip()
                        break
                if not href_text:
                    continue

                is_col = self._webdav_resp_is_collection(resp, href_text)
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
                if is_col:
                    rel_dir = rel.rstrip("/")
                    if skip_assets and "assets" in rel_dir.split("/"):
                        continue
                    if any(part.startswith(".") for part in rel_dir.split("/") if part):
                        continue
                    if norm_dir not in visited:
                        if len(visited) + len(queue) >= max_dirs:
                            raise RuntimeError(self._tr(
                                f"WebDAV 远端目录数量超出扫描上限（{max_dirs} 个），已中止同步以避免遗漏",
                                f"WebDAV remote directory count exceeded the scan limit ({max_dirs}); sync aborted to prevent incomplete results",
                            ))
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
            cur = cur + urllib.parse.quote(part, safe="") + "/"
            try:
                self._webdav_request("MKCOL", cur, cfg=cfg)
            except urllib.error.HTTPError as exc:
                if exc.code not in (405, 301, 302, 409):
                    raise

    def _webdav_get_bytes_with_etag(self, file_url, cfg=None, timeout=6, treat_405_as_absent=False):
        try:
            status, body, headers = self._webdav_request_full("GET", file_url, timeout=timeout, cfg=cfg)
            if 200 <= status < 300:
                return True, body, str(headers.get("etag") or "").strip()
            return False, b"", ""
        except urllib.error.HTTPError as exc:
            if exc.code == 404 or (treat_405_as_absent and exc.code == 405):
                return False, b"", ""
            raise

    def _webdav_get_bytes(self, file_url, cfg=None, timeout=6):
        found, body, _ = self._webdav_get_bytes_with_etag(file_url, cfg=cfg, timeout=timeout)
        return found, body

    def _is_strong_etag(self, etag):
        raw = str(etag or "").strip()
        return bool(raw) and not raw.lower().startswith("w/")

    def _webdav_lock(self, file_url, cfg=None, timeout=6):
        lock_body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<D:lockinfo xmlns:D="DAV:">'
            b'<D:lockscope><D:exclusive/></D:lockscope>'
            b'<D:locktype><D:write/></D:locktype>'
            b'<D:owner><D:href>block-sync</D:href></D:owner>'
            b'</D:lockinfo>'
        )
        try:
            status, body, headers = self._webdav_request_full(
                "LOCK",
                file_url,
                body=lock_body,
                extra_headers={
                    "Content-Type": "application/xml; charset=utf-8",
                    "Depth": "0",
                    "Timeout": "Second-30",
                },
                timeout=timeout,
                cfg=cfg,
                retries=0,
            )
            if status not in (200, 201):
                return None, status
            token = str(headers.get("lock-token") or "").strip()
            if not token and body:
                try:
                    root = ET.fromstring(body)
                    for elem in root.iter():
                        if elem.tag in ("{DAV:}locktoken", "locktoken"):
                            for sub in elem.iter():
                                if sub.tag in ("{DAV:}href", "href") and sub.text:
                                    token = sub.text.strip()
                                    break
                        if token:
                            break
                except ET.ParseError:
                    pass
            if not token:
                return None, status
            if not (token.startswith("<") and token.endswith(">")):
                token = f"<{token}>"
            return token, status
        except urllib.error.HTTPError as exc:
            if exc.code == 423:
                raise
            if exc.code in (405, 501, 400, 403, 404, 412):
                return None, exc.code
            raise

    def _webdav_delete_placeholder(self, file_url, lock_token, cfg=None, timeout=6):
        if not lock_token:
            return True, ""
        # Verify under lock before deleting so we NEVER delete real content saved by a lost-response PUT.
        try:
            found, cur_bytes, _ = self._webdav_get_bytes_with_etag(
                file_url, cfg=cfg, timeout=timeout, treat_405_as_absent=True,
            )
        except Exception as exc:
            return False, self._error_detail(exc)
        if found and len(cur_bytes) > 0:
            # Non-empty content already exists on the server; never delete it.
            return True, ""
        try:
            self._webdav_request_full(
                "DELETE",
                file_url,
                extra_headers={"If": f"({lock_token})"},
                timeout=timeout,
                cfg=cfg,
                retries=2,
            )
            return True, ""
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return True, ""
            return False, self._error_detail(exc)
        except Exception as exc:
            return False, self._error_detail(exc)

    def _webdav_unlock(self, file_url, lock_token, cfg=None, timeout=6):
        if not lock_token:
            return
        try:
            self._webdav_request_full(
                "UNLOCK",
                file_url,
                extra_headers={"Lock-Token": lock_token},
                timeout=timeout,
                cfg=cfg,
                retries=0,
            )
        except Exception:
            pass

    def _webdav_put_conditional(
        self,
        base_url,
        rel_path,
        payload_bytes,
        content_type,
        cfg=None,
        expected_hash=None,
        expected_etag=None,
        create_only=False,
    ):
        self._webdav_ensure_parents(base_url, rel_path, cfg=cfg)
        file_url = base_url + "/".join(urllib.parse.quote(p, safe="") for p in rel_path.split("/"))
        content_hash = sha256_bytes(payload_bytes)
        change_err = self._tr(
            f"WebDAV 远端文件已变更，已中止覆盖以避免数据丢失：{rel_path}",
            f"WebDAV remote file changed during sync; aborted overwrite to protect data: {rel_path}",
        )
        unsafe_err = self._tr(
            f"WebDAV 服务器不支持强 ETag 或写入锁，无法安全执行条件写入：{rel_path}",
            f"WebDAV server lacks strong ETag or write LOCK support for safe conditional write: {rel_path}",
        )
        headers = {"Content-Type": content_type}
        lock_token = None
        created_lock_placeholder = False
        put_outcome_unknown = False
        cleanup_err = ""
        try:
            if create_only:
                found, cur_bytes, _ = self._webdav_get_bytes_with_etag(file_url, cfg=cfg)
                if found:
                    if sha256_bytes(cur_bytes) == content_hash:
                        return
                    raise RuntimeError(change_err)
                lock_token, lock_status = self._webdav_lock(file_url, cfg=cfg)
                if lock_token:
                    headers["If"] = f"({lock_token})"
                    if lock_status == 201:
                        # RFC 4918 §7.3 / §9.10.6: LOCK on an unmapped URL created an empty locked placeholder for us.
                        created_lock_placeholder = True
                    else:
                        # RFC 2518 §7.4: LOCK 200 on a lock-null resource may return 404 or 405 on GET.
                        found2, cur_bytes2, _ = self._webdav_get_bytes_with_etag(
                            file_url, cfg=cfg, treat_405_as_absent=True,
                        )
                        if found2:
                            if sha256_bytes(cur_bytes2) == content_hash:
                                return
                            raise RuntimeError(change_err)
                        created_lock_placeholder = True
                else:
                    headers["If-None-Match"] = "*"
                try:
                    self._webdav_request_full(
                        "PUT", file_url, body=payload_bytes, extra_headers=headers, cfg=cfg,
                    )
                except Exception as put_exc:
                    if lock_token and created_lock_placeholder:
                        is_transport_err = not isinstance(put_exc, urllib.error.HTTPError)
                        if is_transport_err:
                            # PUT outcome is unknown (server may have committed before dropping response).
                            # Verify under lock; if verification GET itself fails, keep the resource for retry
                            # instead of deleting a potentially committed note.
                            put_outcome_unknown = True
                        try:
                            found_after, after_bytes, _ = self._webdav_get_bytes_with_etag(
                                file_url, cfg=cfg, treat_405_as_absent=True,
                            )
                        except Exception:
                            if put_outcome_unknown:
                                created_lock_placeholder = False
                            raise put_exc
                        if found_after:
                            if len(after_bytes) > 0:
                                created_lock_placeholder = False
                                if sha256_bytes(after_bytes) == content_hash:
                                    return
                                raise RuntimeError(change_err) from put_exc
                            if is_transport_err and sha256_bytes(after_bytes) == content_hash:
                                # Server holds our exact intended empty note after a dropped transport response;
                                # treat as committed and never delete it.
                                created_lock_placeholder = False
                                return
                        if put_outcome_unknown:
                            created_lock_placeholder = False
                    raise
                created_lock_placeholder = False
                return
            elif expected_hash is not None:
                if self._is_strong_etag(expected_etag):
                    headers["If-Match"] = expected_etag
                else:
                    lock_token, lock_status = self._webdav_lock(file_url, cfg=cfg)
                    if lock_token:
                        if lock_status == 201:
                            # Target was deleted right before LOCK; clean up the empty placeholder and abort.
                            created_lock_placeholder = True
                            raise RuntimeError(change_err)
                        headers["If"] = f"({lock_token})"
                        found, cur_bytes, _ = self._webdav_get_bytes_with_etag(
                            file_url, cfg=cfg, treat_405_as_absent=True,
                        )
                        if not found:
                            created_lock_placeholder = True
                            raise RuntimeError(change_err)
                        cur_hash = sha256_bytes(cur_bytes)
                        if cur_hash != expected_hash and cur_hash != content_hash:
                            raise RuntimeError(change_err)
                    else:
                        found, cur_bytes, cur_etag = self._webdav_get_bytes_with_etag(file_url, cfg=cfg)
                        if not found:
                            raise RuntimeError(change_err)
                        cur_hash = sha256_bytes(cur_bytes)
                        if cur_hash != expected_hash and cur_hash != content_hash:
                            raise RuntimeError(change_err)
                        if not self._is_strong_etag(cur_etag):
                            raise RuntimeError(unsafe_err)
                        headers["If-Match"] = cur_etag
            try:
                self._webdav_request("PUT", file_url, body=payload_bytes, extra_headers=headers, cfg=cfg)
            except Exception as put_exc:
                if lock_token and not isinstance(put_exc, urllib.error.HTTPError):
                    # Verify under lock if server actually committed our PUT before dropping the response.
                    try:
                        found_after, after_bytes, _ = self._webdav_get_bytes_with_etag(
                            file_url, cfg=cfg, treat_405_as_absent=True,
                        )
                    except Exception:
                        found_after, after_bytes = False, b""
                    if found_after and sha256_bytes(after_bytes) == content_hash:
                        return
                raise
        except urllib.error.HTTPError as exc:
            if exc.code == 412:
                found, cur_bytes, _ = self._webdav_get_bytes_with_etag(file_url, cfg=cfg)
                if found and sha256_bytes(cur_bytes) == content_hash:
                    created_lock_placeholder = False
                    return
                raise RuntimeError(change_err) from exc
            if exc.code == 423:
                raise RuntimeError(change_err) from exc
            raise
        finally:
            if lock_token:
                if created_lock_placeholder:
                    ok_del, del_detail = self._webdav_delete_placeholder(file_url, lock_token, cfg=cfg)
                    if not ok_del:
                        cleanup_err = del_detail
                self._webdav_unlock(file_url, lock_token, cfg=cfg)
                if cleanup_err:
                    raise RuntimeError(self._tr(
                        f"WebDAV 写入失败且清理临时占位文件失败（{rel_path}）：{cleanup_err}",
                        f"WebDAV write failed and empty placeholder cleanup also failed ({rel_path}): {cleanup_err}",
                    ))

    def _webdav_put_text(self, base_url, rel_path, content, cfg=None, expected_hash=None, expected_etag=None, create_only=False):
        self._webdav_put_conditional(
            base_url,
            rel_path,
            content.encode("utf-8"),
            "text/markdown; charset=utf-8",
            cfg=cfg,
            expected_hash=expected_hash,
            expected_etag=expected_etag,
            create_only=create_only,
        )

    def _webdav_put_bytes(self, base_url, rel_path, data, cfg=None, expected_hash=None, expected_etag=None, create_only=False):
        self._webdav_put_conditional(
            base_url,
            rel_path,
            data,
            "application/octet-stream",
            cfg=cfg,
            expected_hash=expected_hash,
            expected_etag=expected_etag,
            create_only=create_only,
        )

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

    def _is_managed_git_dir(self, repo_dir):
        if not repo_dir:
            return False
        managed_root = os.path.realpath(os.path.join(self.data_dir or os.getcwd(), "git-repos"))
        return os.path.realpath(repo_dir).startswith(managed_root + os.sep)

    def _git_current_branch(self, repo_dir, cfg=None):
        proc = self._run_git(["symbolic-ref", "--short", "HEAD"], cwd=repo_dir, cfg=cfg)
        if proc.returncode == 0:
            return proc.stdout.strip()
        return ""

    def _git_repo_dirs(self, cfg):
        target = str(cfg.get("git_remote") or "").strip()
        branch = self._git_branch(cfg)
        if target and not self._is_remote_git_url(target):
            expanded = os.path.expanduser(target)
            base = self.data_dir or os.getcwd()
            path = os.path.normpath(os.path.join(base, expanded))
            return [path]
        base = os.path.join(self.data_dir or os.getcwd(), "git-repos")
        if not target:
            return [os.path.join(base, self._notebook_slug())]

        repo_key = f"{target}\n{branch}"
        canonical = os.path.join(base, f"repo-{sha256_text(repo_key)[:12]}")
        legacy = []
        legacy_unbranched = os.path.join(base, f"repo-{sha256_text(target)[:12]}")
        if os.path.isdir(base) and shutil.which("git"):
            candidates = []
            if legacy_unbranched != canonical and self._has_git_marker(legacy_unbranched):
                candidates.append(legacy_unbranched)
            for name in sorted(os.listdir(base)):
                path = os.path.join(base, name)
                if path in (canonical, legacy_unbranched) or not re.search(r"-[0-9a-f]{8}$", name):
                    continue
                if self._has_git_marker(path):
                    candidates.append(path)
            for path in candidates:
                result = self._run_git(["config", "--local", "--get", "remote.origin.url"], cwd=path, cfg=cfg)
                if result.returncode == 0 and result.stdout.strip() == target:
                    cur_branch = self._git_current_branch(path, cfg=cfg)
                    if cur_branch == branch:
                        legacy.append(path)
        return [canonical, *legacy]

    def _resolve_local_git_dir(self, cfg=None):
        dirs = self._git_repo_dirs(cfg or self.config)
        return next((path for path in dirs if self._has_git_marker(path)), dirs[0])

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

    def _git_remote_heads(self, target, cfg=None, cwd=None, timeout=10, retries=1, total_budget=18.0):
        proc = self._run_git_network(
            ["ls-remote", "--heads", target],
            cwd=cwd,
            timeout=timeout,
            cfg=cfg,
            retries=retries,
            total_budget=total_budget,
        )
        if proc.returncode != 0:
            err = self._git_error_message(proc.stderr or proc.stdout, self._tr("连接失败", "Connection failed"))
            return False, err
        heads = []
        for line in (proc.stdout or "").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[1].startswith("refs/heads/"):
                heads.append(parts[1][len("refs/heads/"):])
        return True, heads

    def _git_path(self, repo_dir, rel, cfg=None):
        proc = self._run_git(["rev-parse", "--git-path", rel], cwd=repo_dir, cfg=cfg)
        if proc.returncode == 0 and proc.stdout.strip():
            raw = proc.stdout.strip()
            return raw if os.path.isabs(raw) else os.path.join(repo_dir, raw)
        git_dir = self._resolve_git_dir(repo_dir)
        return os.path.join(git_dir, rel) if git_dir else ""

    def _load_git_pushed_refs(self, repo_dir, cfg=None):
        p = self._git_path(repo_dir, "block-sync-pushed-refs.json", cfg=cfg)
        if not p or not os.path.isfile(p):
            return {}
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _record_git_synced_branch(self, repo_dir, branch, oid, remote_name="origin", cfg=None):
        oid = str(oid or "").strip()
        if not oid or not branch:
            return
        p = self._git_path(repo_dir, "block-sync-pushed-refs.json", cfg=cfg)
        if not p:
            return
        try:
            data = self._load_git_pushed_refs(repo_dir, cfg=cfg)
            data[f"{remote_name}:{branch}"] = oid
            data.pop(f"pending_initial:{remote_name}:{branch}", None)
            tmp_p = f"{p}.{os.getpid()}.tmp"
            with open(tmp_p, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, sort_keys=True)
            os.replace(tmp_p, p)
        except Exception:
            pass

    def _record_git_pending_initial(self, repo_dir, branch, oid, remote_name="origin", cfg=None):
        oid = str(oid or "").strip()
        if not oid or not branch:
            return
        p = self._git_path(repo_dir, "block-sync-pushed-refs.json", cfg=cfg)
        if not p:
            return
        try:
            data = self._load_git_pushed_refs(repo_dir, cfg=cfg)
            if not data.get(f"{remote_name}:{branch}"):
                data[f"pending_initial:{remote_name}:{branch}"] = oid
                tmp_p = f"{p}.{os.getpid()}.tmp"
                with open(tmp_p, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, ensure_ascii=False, sort_keys=True)
                os.replace(tmp_p, p)
        except Exception:
            pass

    def _has_git_pending_initial(self, repo_dir, branch, remote_name="origin", cfg=None):
        if not repo_dir or not branch or not self._has_git_marker(repo_dir):
            return False
        data = self._load_git_pushed_refs(repo_dir, cfg=cfg)
        return bool(data.get(f"pending_initial:{remote_name}:{branch}")) and not bool(data.get(f"{remote_name}:{branch}"))

    def _get_git_synced_branch_oid(self, repo_dir, branch, remote_name="origin", cfg=None):
        if not repo_dir or not branch or not self._has_git_marker(repo_dir):
            return ""
        ref_proc = self._run_git(
            ["rev-parse", "--verify", f"refs/remotes/{remote_name}/{branch}"],
            cwd=repo_dir,
            cfg=cfg,
        )
        if ref_proc.returncode == 0 and ref_proc.stdout.strip():
            return ref_proc.stdout.strip()
        data = self._load_git_pushed_refs(repo_dir, cfg=cfg)
        return str(data.get(f"{remote_name}:{branch}") or "").strip()

    def _git_branch_has_upstream_config(self, repo_dir, branch, remote_name="origin", cfg=None):
        if not repo_dir or not branch or not self._has_git_marker(repo_dir):
            return False
        if self._run_git(["rev-parse", "--verify", f"refs/heads/{branch}"], cwd=repo_dir, cfg=cfg).returncode != 0:
            return False
        r_proc = self._run_git(["config", "--get", f"branch.{branch}.remote"], cwd=repo_dir, cfg=cfg)
        if r_proc.returncode != 0 or r_proc.stdout.strip() != remote_name:
            return False
        m_proc = self._run_git(["config", "--get", f"branch.{branch}.merge"], cwd=repo_dir, cfg=cfg)
        if m_proc.returncode != 0:
            return False
        return m_proc.stdout.strip() in (f"refs/heads/{branch}", branch)

    def _was_git_branch_synced(self, repo_dir, branch, remote_name="origin", cfg=None):
        if self._get_git_synced_branch_oid(repo_dir, branch, remote_name=remote_name, cfg=cfg):
            return True
        if self._has_git_pending_initial(repo_dir, branch, remote_name=remote_name, cfg=cfg):
            return False
        return self._git_branch_has_upstream_config(repo_dir, branch, remote_name=remote_name, cfg=cfg)

    def _test_git(self):
        if not shutil.which("git"):
            return False, self._tr("当前环境未安装 git 命令", "Git is not installed")
        target = self.config.get("git_remote", "").strip()
        branch = self._git_branch()
        try:
            if target and self._is_remote_git_url(target):
                ok, res = self._git_remote_heads(target, cfg=self.config, timeout=10, retries=1, total_budget=20.0)
                if not ok:
                    return False, self._tr(f"Git 远端不可达: {res}", f"Git remote is unreachable: {res}")
                heads = res
                if not heads:
                    repo_dir = self._resolve_local_git_dir(self.config)
                    if self._was_git_branch_synced(repo_dir, branch, remote_name="origin", cfg=self.config):
                        return False, self._tr(
                            f"远端分支 {branch} 已不存在（疑似被删除或重置），请先确认远端状态",
                            f"Remote branch {branch} no longer exists (it may have been deleted or reset); verify remote state first",
                        )
                    return True, self._tr(
                        f"Git 远端为空仓库（首次同步将创建分支 {branch}）",
                        f"Git remote is empty (first sync will create branch {branch})",
                    )
                if branch in heads:
                    return True, self._tr(
                        f"Git 远端仓库连接正常（分支 {branch}）",
                        f"Git remote connection successful (branch: {branch})",
                    )
                avail = ", ".join(heads[:4]) + ("..." if len(heads) > 4 else "")
                return False, self._tr(
                    f"远端仓库不存在分支 {branch}（已有分支：{avail}）",
                    f"Remote branch {branch} does not exist (available: {avail})",
                )

            repo_dir = self._resolve_local_git_dir()
            if not os.path.isdir(repo_dir):
                return False, self._tr(f"本地 Git 仓库目录不存在: {repo_dir}", f"Local Git repository folder does not exist: {repo_dir}")
            proc = self._run_git(["rev-parse", "--is-inside-work-tree"], cwd=repo_dir)
            if proc.returncode != 0 or proc.stdout.strip() != "true":
                return False, self._tr(f"目录不是有效的 Git 仓库: {repo_dir}", f"Folder is not a valid Git repository: {repo_dir}")
            remote_proc = self._run_git(["remote"], cwd=repo_dir)
            remotes = [r.strip() for r in remote_proc.stdout.splitlines() if r.strip()]
            if remotes:
                remote_name = "origin" if "origin" in remotes else remotes[0]
                ok, res = self._git_remote_heads(remote_name, cfg=self.config, cwd=repo_dir, timeout=10, retries=1, total_budget=20.0)
                if ok:
                    if not res and self._was_git_branch_synced(repo_dir, branch, remote_name=remote_name, cfg=self.config):
                        return False, self._tr(
                            f"远端 {remote_name} 的分支 {branch} 已不存在（疑似被删除或重置），请先确认远端状态",
                            f"Remote {remote_name} branch {branch} no longer exists (it may have been deleted or reset); verify remote state first",
                        )
                    if not res or branch in res:
                        return True, self._tr(f"Git 仓库及远端 {remote_name} 正常", f"Git repository and remote {remote_name} are available")
                    avail = ", ".join(res[:4]) + ("..." if len(res) > 4 else "")
                    return False, self._tr(
                        f"远端 {remote_name} 不存在分支 {branch}（已有分支：{avail}）",
                        f"Remote {remote_name} does not have branch {branch} (available: {avail})",
                    )
                return True, self._tr(f"本地 Git 仓库可用（远端 {remote_name} 当前离线）", f"Local Git repository is available (remote {remote_name} is offline)")
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
            ok_heads, heads_or_err = self._git_remote_heads(target, cfg=cfg, timeout=10, retries=2, total_budget=22.0)
            if not ok_heads:
                return False, self._tr(f"Git 远端不可达: {heads_or_err}", f"Git remote is unreachable: {heads_or_err}")
            heads = heads_or_err
            if heads and branch not in heads:
                avail = ", ".join(heads[:4]) + ("..." if len(heads) > 4 else "")
                return False, self._tr(
                    f"远端仓库不存在分支 {branch}（已有分支：{avail}），请核对分支名后重试",
                    f"Remote branch {branch} does not exist (available: {avail}); check the branch name and retry",
                )

            if not heads:
                # Empty remote repository: initialize cleanly on the configured branch without pulling any other branch.
                if not self._has_git_marker(repo_dir):
                    if not allow_init_or_clone:
                        return False, None
                    os.makedirs(repo_dir, exist_ok=True)
                    init_proc = self._run_git(["init", "-b", branch], cwd=repo_dir, cfg=cfg)
                    if init_proc.returncode != 0:
                        init_proc = self._run_git(["init"], cwd=repo_dir, cfg=cfg)
                        if init_proc.returncode == 0:
                            self._run_git(["symbolic-ref", "HEAD", f"refs/heads/{branch}"], cwd=repo_dir, cfg=cfg)
                    if init_proc.returncode != 0:
                        return False, self._tr("Git 仓库初始化失败", "Could not initialize the Git repository")
                    self._run_git(["remote", "add", "origin", target], cwd=repo_dir, cfg=cfg)
                else:
                    url_proc = self._run_git(["remote", "get-url", "origin"], cwd=repo_dir, cfg=cfg)
                    if url_proc.returncode != 0:
                        self._run_git(["remote", "add", "origin", target], cwd=repo_dir, cfg=cfg)
                    elif url_proc.stdout.strip() != target:
                        self._run_git(["remote", "set-url", "origin", target], cwd=repo_dir, cfg=cfg)
                    if self._is_managed_git_dir(repo_dir):
                        # If we previously synced with origin/<branch> (tracking ref, upstream config, or ledger exists)
                        # and the remote now has no branches, the remote branch was deleted or reset — abort
                        # loudly instead of silently pushing local history back to origin or wiping the cache.
                        if self._was_git_branch_synced(repo_dir, branch, remote_name="origin", cfg=cfg):
                            return False, self._tr(
                                f"远端分支 {branch} 已不存在（疑似被删除或重置），为避免未经确认重建远端历史已中止同步",
                                f"Remote branch {branch} no longer exists (it may have been deleted or reset); sync aborted to avoid silently recreating remote history",
                            )
                        # Before resetting a managed cache against an empty remote, check if our target branch
                        # already has unpushed local commits (e.g. first push rejected by a receive hook).
                        local_ref = f"refs/heads/{branch}"
                        if self._run_git(["rev-parse", "--verify", local_ref], cwd=repo_dir, cfg=cfg).returncode == 0:
                            retry_push = self._run_git_network(
                                ["push", f"--force-with-lease=refs/heads/{branch}:", "-u", "origin", f"{local_ref}:{local_ref}"],
                                cwd=repo_dir,
                                timeout=12,
                                cfg=cfg,
                                retries=2,
                                total_budget=22.0,
                            )
                            if retry_push.returncode == 0:
                                self._run_git_network(
                                    ["fetch", "origin", f"refs/heads/{branch}:refs/remotes/origin/{branch}"],
                                    cwd=repo_dir,
                                    timeout=12,
                                    cfg=cfg,
                                    retries=1,
                                    total_budget=15.0,
                                )
                                oid_p = self._run_git(["rev-parse", "--verify", f"refs/remotes/origin/{branch}"], cwd=repo_dir, cfg=cfg)
                                if oid_p.returncode == 0 and oid_p.stdout.strip():
                                    self._record_git_synced_branch(repo_dir, branch, oid_p.stdout.strip(), remote_name="origin", cfg=cfg)
                                return True, repo_dir
                            backup_ref = f"pending-push-{branch}-{int(time.time())}"
                            self._run_git(["branch", "-f", backup_ref, local_ref], cwd=repo_dir, cfg=cfg)
                            err = self._git_error_message(retry_push.stderr or retry_push.stdout, self._tr("push 失败", "Push failed"))
                            return False, self._tr(
                                f"上次未推送的 Git 首次提交重试推送失败（已保留于分支 {backup_ref}）: {err}",
                                f"Retry push of pending initial Git commit failed (preserved on branch {backup_ref}): {err}",
                            )
                        # Reset unborn/stale managed cache (no commits on target branch) so an empty remote
                        # never inherits commits from another branch.
                        head_chk = self._run_git(["rev-parse", "--verify", "HEAD"], cwd=repo_dir, cfg=cfg)
                        if head_chk.returncode == 0:
                            shutil.rmtree(repo_dir, ignore_errors=True)
                            os.makedirs(repo_dir, exist_ok=True)
                            init_proc = self._run_git(["init", "-b", branch], cwd=repo_dir, cfg=cfg)
                            if init_proc.returncode != 0:
                                self._run_git(["init"], cwd=repo_dir, cfg=cfg)
                                self._run_git(["symbolic-ref", "HEAD", f"refs/heads/{branch}"], cwd=repo_dir, cfg=cfg)
                            self._run_git(["remote", "add", "origin", target], cwd=repo_dir, cfg=cfg)
                        else:
                            self._run_git(["symbolic-ref", "HEAD", f"refs/heads/{branch}"], cwd=repo_dir, cfg=cfg)
                            clean_flags = "-fdx" if self._is_managed_git_dir(repo_dir) else "-fd"
                            self._run_git(["clean", clean_flags], cwd=repo_dir, cfg=cfg)
                return True, repo_dir

            # Remote has the requested branch.
            if not self._has_git_marker(repo_dir):
                if not allow_init_or_clone:
                    return False, None
                os.makedirs(os.path.dirname(repo_dir), exist_ok=True)
                existed_before = os.path.exists(repo_dir)

                def _cleanup_partial_clone():
                    if not existed_before and os.path.exists(repo_dir):
                        shutil.rmtree(repo_dir, ignore_errors=True)

                clone_proc = self._run_git_network(
                    ["clone", "--branch", branch, "--single-branch", target, repo_dir],
                    timeout=15,
                    cfg=cfg,
                    retries=2,
                    total_budget=30.0,
                    on_retry=_cleanup_partial_clone,
                )
                if clone_proc.returncode != 0:
                    _cleanup_partial_clone()
                    err = self._git_error_message(clone_proc.stderr or clone_proc.stdout, self._tr("clone 失败", "Clone failed"))
                    return False, self._tr(f"Git 远端不可达: {err}", f"Git remote is unreachable: {err}")
                oid_p = self._run_git(["rev-parse", "--verify", f"refs/remotes/origin/{branch}"], cwd=repo_dir, cfg=cfg)
                if oid_p.returncode == 0 and oid_p.stdout.strip():
                    self._record_git_synced_branch(repo_dir, branch, oid_p.stdout.strip(), remote_name="origin", cfg=cfg)
            else:
                url_proc = self._run_git(["remote", "get-url", "origin"], cwd=repo_dir, cfg=cfg)
                if url_proc.returncode != 0:
                    self._run_git(["remote", "add", "origin", target], cwd=repo_dir, cfg=cfg)
                elif url_proc.stdout.strip() != target:
                    self._run_git(["remote", "set-url", "origin", target], cwd=repo_dir, cfg=cfg)
                if allow_pull:
                    self._run_git(["rebase", "--abort"], cwd=repo_dir, cfg=cfg)
                    self._run_git(["merge", "--abort"], cwd=repo_dir, cfg=cfg)
                    fetch_proc = self._run_git_network(
                        ["fetch", "origin", f"refs/heads/{branch}:refs/remotes/origin/{branch}"],
                        cwd=repo_dir,
                        timeout=12,
                        cfg=cfg,
                        retries=2,
                        total_budget=22.0,
                    )
                    if fetch_proc.returncode != 0:
                        err = self._git_error_message(fetch_proc.stderr or fetch_proc.stdout, self._tr("fetch 失败", "Fetch failed"))
                        return False, self._tr(f"Git 拉取失败: {err}", f"Git pull failed: {err}")
                    oid_p = self._run_git(["rev-parse", "--verify", f"refs/remotes/origin/{branch}"], cwd=repo_dir, cfg=cfg)
                    if oid_p.returncode == 0 and oid_p.stdout.strip():
                        self._record_git_synced_branch(repo_dir, branch, oid_p.stdout.strip(), remote_name="origin", cfg=cfg)
                    # Before resetting a managed clone to origin/<branch>, check for unpushed local commits
                    # (e.g. from a prior push rejected by a receive hook or transient outage) so they are never lost.
                    if self._is_managed_git_dir(repo_dir):
                        local_ref = f"refs/heads/{branch}"
                        remote_ref = f"refs/remotes/origin/{branch}"
                        if self._run_git(["rev-parse", "--verify", local_ref], cwd=repo_dir, cfg=cfg).returncode == 0:
                            ahead_p = self._run_git(["rev-list", "--count", f"{remote_ref}..{local_ref}"], cwd=repo_dir, cfg=cfg)
                            behind_p = self._run_git(["rev-list", "--count", f"{local_ref}..{remote_ref}"], cwd=repo_dir, cfg=cfg)
                            ahead_n = int((ahead_p.stdout or "0").strip() or "0") if ahead_p.returncode == 0 else 0
                            behind_n = int((behind_p.stdout or "0").strip() or "0") if behind_p.returncode == 0 else 0
                            if ahead_n > 0:
                                if behind_n == 0:
                                    exp_oid_p = self._run_git(["rev-parse", "--verify", remote_ref], cwd=repo_dir, cfg=cfg)
                                    exp_oid = exp_oid_p.stdout.strip() if exp_oid_p.returncode == 0 else ""
                                    lease_arg = f"--force-with-lease=refs/heads/{branch}:{exp_oid}"
                                    retry_push = self._run_git_network(
                                        ["push", lease_arg, "-u", "origin", f"{local_ref}:{local_ref}"],
                                        cwd=repo_dir,
                                        timeout=12,
                                        cfg=cfg,
                                        retries=2,
                                        total_budget=22.0,
                                    )
                                    if retry_push.returncode == 0:
                                        self._run_git_network(
                                            ["fetch", "origin", f"refs/heads/{branch}:refs/remotes/origin/{branch}"],
                                            cwd=repo_dir,
                                            timeout=12,
                                            cfg=cfg,
                                            retries=1,
                                            total_budget=15.0,
                                        )
                                        oid_p2 = self._run_git(["rev-parse", "--verify", remote_ref], cwd=repo_dir, cfg=cfg)
                                        if oid_p2.returncode == 0 and oid_p2.stdout.strip():
                                            self._record_git_synced_branch(repo_dir, branch, oid_p2.stdout.strip(), remote_name="origin", cfg=cfg)
                                    else:
                                        backup_ref = f"pending-push-{branch}-{int(time.time())}"
                                        self._run_git(["branch", "-f", backup_ref, local_ref], cwd=repo_dir, cfg=cfg)
                                        err = self._git_error_message(retry_push.stderr or retry_push.stdout, self._tr("push 失败", "Push failed"))
                                        return False, self._tr(
                                            f"上次未推送的 Git 提交重试推送失败（已保留于分支 {backup_ref}）: {err}",
                                            f"Retry push of pending Git commits failed (preserved on branch {backup_ref}): {err}",
                                        )
                                else:
                                    backup_ref = f"pending-push-{branch}-{int(time.time())}"
                                    self._run_git(["branch", "-f", backup_ref, local_ref], cwd=repo_dir, cfg=cfg)
                                    return False, self._tr(
                                        f"检测到 {ahead_n} 个尚未推送的本地提交与远端 {branch} 分叉，已保留于分支 {backup_ref}，请先处理分叉",
                                        f"Found {ahead_n} unpushed local commits diverged from remote {branch}; preserved on branch {backup_ref}",
                                    )
                    # Managed clone reflects remote HEAD directly; Block's 3-way sync planner resolves
                    # any divergence against the user's real notebook using the configured conflict_policy.
                    # Force-checkout when inside plugin-managed git-repos/ so leftover dirty files from an
                    # earlier failed sync (e.g. .gitignore rejection) never deadlock recovery on retry.
                    co_args = ["checkout", "-f", "-B", branch, f"refs/remotes/origin/{branch}"] if self._is_managed_git_dir(repo_dir) else ["checkout", "-B", branch, f"refs/remotes/origin/{branch}"]
                    co_proc = self._run_git(co_args, cwd=repo_dir, cfg=cfg)
                    if co_proc.returncode != 0:
                        err = self._git_error_message(co_proc.stderr or co_proc.stdout, self._tr("切换分支失败", "Checkout failed"))
                        return False, self._tr(f"Git 切换分支失败: {err}", f"Git branch checkout failed: {err}")
                    self._run_git(["reset", "--hard", f"refs/remotes/origin/{branch}"], cwd=repo_dir, cfg=cfg)
                    clean_flags = "-fdx" if self._is_managed_git_dir(repo_dir) else "-fd"
                    self._run_git(["clean", clean_flags], cwd=repo_dir, cfg=cfg)
        else:
            if not self._has_git_marker(repo_dir):
                if not allow_init_or_clone:
                    return False, None
                os.makedirs(repo_dir, exist_ok=True)
                init_proc = self._run_git(["init", "-b", branch], cwd=repo_dir, cfg=cfg)
                if init_proc.returncode != 0:
                    init_proc = self._run_git(["init"], cwd=repo_dir, cfg=cfg)
                    if init_proc.returncode == 0:
                        self._run_git(["symbolic-ref", "HEAD", f"refs/heads/{branch}"], cwd=repo_dir, cfg=cfg)
                if init_proc.returncode != 0:
                    return False, self._tr("Git 仓库初始化失败", "Could not initialize the Git repository")
            else:
                cur_branch = self._git_current_branch(repo_dir, cfg=cfg)
                if cur_branch != branch:
                    cur_label = cur_branch or "detached HEAD"
                    st_proc = self._run_git(["status", "--porcelain"], cwd=repo_dir, cfg=cfg)
                    if st_proc.returncode == 0 and st_proc.stdout.strip():
                        return False, self._tr(
                            f"本地 Git 仓库当前位于 {cur_label} 且有未提交改动，无法切换到 {branch}",
                            f"Local Git repository is at {cur_label} with uncommitted changes; cannot switch to {branch}",
                        )
                    chk_ref = self._run_git(["rev-parse", "--verify", f"refs/heads/{branch}"], cwd=repo_dir, cfg=cfg)
                    if chk_ref.returncode == 0:
                        co_proc = self._run_git(["checkout", branch], cwd=repo_dir, cfg=cfg)
                        if co_proc.returncode != 0:
                            err = self._git_error_message(co_proc.stderr or co_proc.stdout, self._tr("切换分支失败", "Checkout failed"))
                            return False, self._tr(f"Git 切换分支失败: {err}", f"Git branch checkout failed: {err}")
                    else:
                        return False, self._tr(
                            f"本地 Git 仓库当前位于 {cur_label}，目标分支 {branch} 不存在",
                            f"Local Git repository is at {cur_label} and target branch {branch} does not exist",
                        )
                if allow_pull:
                    remote_proc = self._run_git(["remote"], cwd=repo_dir, cfg=cfg)
                    remotes = [r.strip() for r in (remote_proc.stdout or "").splitlines() if r.strip()] if remote_proc.returncode == 0 else []
                    if remotes:
                        remote_name = "origin" if "origin" in remotes else remotes[0]
                        ok_heads, heads_or_err = self._git_remote_heads(remote_name, cfg=cfg, cwd=repo_dir, timeout=10, retries=1, total_budget=18.0)
                        if not ok_heads:
                            return False, self._tr(f"Git 远端拉取失败: {heads_or_err}", f"Git remote pull failed: {heads_or_err}")
                        if heads_or_err and branch not in heads_or_err:
                            avail = ", ".join(heads_or_err[:4]) + ("..." if len(heads_or_err) > 4 else "")
                            return False, self._tr(
                                f"远端 {remote_name} 不存在分支 {branch}（已有分支：{avail}）",
                                f"Remote {remote_name} does not have branch {branch} (available: {avail})",
                            )
                        if not heads_or_err and self._was_git_branch_synced(repo_dir, branch, remote_name=remote_name, cfg=cfg):
                            return False, self._tr(
                                f"远端 {remote_name} 的分支 {branch} 已不存在（疑似被删除或重置），为避免未经确认重建远端历史已中止同步",
                                f"Remote {remote_name} branch {branch} no longer exists (it may have been deleted or reset); sync aborted to avoid silently recreating remote history",
                            )
                        if branch in heads_or_err:
                            fetch_proc = self._run_git_network(
                                ["fetch", remote_name, f"refs/heads/{branch}:refs/remotes/{remote_name}/{branch}"],
                                cwd=repo_dir,
                                timeout=12,
                                cfg=cfg,
                                retries=2,
                                total_budget=22.0,
                            )
                            if fetch_proc.returncode != 0:
                                err = self._git_error_message(fetch_proc.stderr or fetch_proc.stdout, self._tr("fetch 失败", "Fetch failed"))
                                return False, self._tr(f"Git 拉取失败: {err}", f"Git pull failed: {err}")
                            oid_p = self._run_git(["rev-parse", "--verify", f"refs/remotes/{remote_name}/{branch}"], cwd=repo_dir, cfg=cfg)
                            if oid_p.returncode == 0 and oid_p.stdout.strip():
                                self._record_git_synced_branch(repo_dir, branch, oid_p.stdout.strip(), remote_name=remote_name, cfg=cfg)
                            head_chk = self._run_git(["rev-parse", "--verify", "HEAD"], cwd=repo_dir, cfg=cfg)
                            if head_chk.returncode != 0:
                                self._run_git(["checkout", "-B", branch, f"refs/remotes/{remote_name}/{branch}"], cwd=repo_dir, cfg=cfg)
                            else:
                                ff_proc = self._run_git(["merge", "--ff-only", f"refs/remotes/{remote_name}/{branch}"], cwd=repo_dir, cfg=cfg)
                                if ff_proc.returncode != 0:
                                    err = self._git_error_message(ff_proc.stderr or ff_proc.stdout, self._tr("分支已分叉", "Branches diverged"))
                                    return False, self._tr(
                                        f"本地 Git 仓库与远端 {remote_name}/{branch} 已分叉，请先手动合并：{err}",
                                        f"Local Git repository diverged from {remote_name}/{branch}; resolve manually: {err}",
                                    )

        return True, repo_dir

    def _webdav_list_dir_entries(self, base_url, dir_parts, cfg=None, timeout=6):
        """Return (rel_path, is_collection) direct children of base_url/dir_parts via one Depth: 1 PROPFIND."""
        dir_url = base_url + ("/".join(urllib.parse.quote(p, safe="") for p in dir_parts) + "/" if dir_parts else "")
        root_path = urllib.parse.unquote(urllib.parse.urlparse(base_url).path).rstrip("/") + "/"
        if not root_path.startswith("/"):
            root_path = "/" + root_path
        dir_path = urllib.parse.unquote(urllib.parse.urlparse(dir_url).path).rstrip("/") + "/"
        dav_ns = "{DAV:}"
        try:
            status, body = self._webdav_request("PROPFIND", dir_url, extra_headers={"Depth": "1"}, timeout=timeout, cfg=cfg)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return []
            raise
        if status not in (200, 207):
            return []
        entries = []
        root = ET.fromstring(body)
        for resp in (elem for elem in root.iter() if elem.tag in (f"{dav_ns}response", "response")):
            href_text = ""
            for child in list(resp):
                if child.tag in (f"{dav_ns}href", "href") and child.text:
                    href_text = child.text.strip()
                    break
            if not href_text:
                continue
            is_col = self._webdav_resp_is_collection(resp, href_text)
            abs_href = urllib.parse.urljoin(dir_url, href_text)
            href_path = urllib.parse.unquote(urllib.parse.urlparse(abs_href).path)
            if href_path.rstrip("/") + "/" == dir_path or not href_path.startswith(root_path):
                continue
            rel = href_path[len(root_path):].lstrip("/").rstrip("/")
            if rel:
                entries.append((rel, is_col))
        return entries

    def _webdav_resolve_dir_case_variants(self, base_url, dir_parts, cfg=None, timeout=6):
        """Find all remote directory paths matching dir_parts case-insensitively."""
        if not dir_parts:
            return [[]]
        cur_prefixes = [[]]
        for seg in dir_parts:
            seg_cf = seg.casefold()
            next_prefixes = []
            seen = set()
            for prefix in cur_prefixes:
                for rel, is_col in self._webdav_list_dir_entries(base_url, prefix, cfg=cfg, timeout=timeout):
                    if not is_col:
                        continue
                    name = rel.split("/")[-1]
                    if name.casefold() == seg_cf:
                        cand = tuple(prefix) + (name,)
                        if cand not in seen:
                            seen.add(cand)
                            next_prefixes.append(list(cand))
            if not next_prefixes:
                return []
            cur_prefixes = next_prefixes
        return cur_prefixes

    def _webdav_list_scoped(self, base_url, filter_fn, scope="all", cfg=None, timeout=6, excluded_subdirs=(), skip_assets=False):
        sc = str(scope or "all").strip().strip("/")
        if not sc or sc == "all":
            return self._webdav_list_files(
                base_url, filter_fn, cfg=cfg, timeout=timeout, excluded_subdirs=excluded_subdirs, skip_assets=skip_assets,
            )
        sc_parts = [p for p in sc.split("/") if p]
        dir_variants = self._webdav_resolve_dir_case_variants(base_url, sc_parts, cfg=cfg, timeout=timeout)
        if not dir_variants:
            dir_variants = [sc_parts]
        out = []
        seen = set()
        for parts in dir_variants:
            sc_actual = "/".join(parts)
            scope_prefix = "/".join(urllib.parse.quote(p, safe="") for p in parts)
            scope_url = base_url + scope_prefix + "/"
            sub_items = self._webdav_list_files(
                scope_url, lambda rel, _p=sc_actual: filter_fn(f"{_p}/{rel}"), cfg=cfg, timeout=timeout, skip_assets=skip_assets,
            )
            for rel in sub_items:
                full_rel = f"{sc_actual}/{rel}"
                if full_rel not in seen and not in_sync_subdir(full_rel, excluded_subdirs):
                    seen.add(full_rel)
                    out.append(full_rel)
        return out

    def _webdav_find_case_variants(self, base_url, only_path, scope="all", cfg=None, timeout=6, excluded_subdirs=(), filter_fn=None):
        """Locate remote WebDAV files differing from only_path only in letter case (including parent folders)."""
        check_fn = filter_fn or is_safe_rel_md
        target_cf = only_path.casefold()
        parts = [p for p in only_path.split("/") if p]
        if not parts:
            return []
        parent_variants = self._webdav_resolve_dir_case_variants(base_url, parts[:-1], cfg=cfg, timeout=timeout)
        matches = []
        seen = set()
        for pv in parent_variants:
            for rel, is_col in self._webdav_list_dir_entries(base_url, pv, cfg=cfg, timeout=timeout):
                if is_col:
                    continue
                if rel != only_path and rel.casefold() == target_cf and check_fn(rel) and not in_sync_subdir(rel, excluded_subdirs):
                    if rel not in seen:
                        seen.add(rel)
                        matches.append(rel)
        return matches

    def _fetch_webdav_notes(self, cfg, only_path=None, scope="all", timeout=6, force_refresh=False, subdir="", excluded_subdirs=()):
        root_url = self._webdav_root_url(cfg)
        base_url = self._webdav_base_url(cfg, subdir=subdir)
        if not root_url or not base_url:
            return False, {}, {}, self._tr("请先填写有效的 WebDAV http(s) 地址", "Enter a valid HTTP or HTTPS WebDAV address first")

        cache_key = (base_url, scope, only_path or "", frozenset(excluded_subdirs))
        if not force_refresh and only_path is None and cache_key in self._remote_preview_cache:
            cached_ts, cached_notes, cached_etags = self._remote_preview_cache[cache_key]
            if time.time() - cached_ts < 15.0:
                return True, dict(cached_notes), dict(cached_etags), None

        try:
            remote_paths = (
                [only_path]
                if only_path
                else self._webdav_list_scoped(
                    base_url, is_safe_rel_md, scope=scope, cfg=cfg, timeout=timeout,
                    excluded_subdirs=excluded_subdirs, skip_assets=True,
                )
            )
            remote_notes = {}
            remote_etags = {}
            for rel_path in remote_paths:
                if not is_safe_rel_md(rel_path) or is_safe_rel_asset(rel_path) or in_sync_subdir(rel_path, excluded_subdirs):
                    continue
                file_url = base_url + "/".join(urllib.parse.quote(p, safe="") for p in rel_path.split("/"))
                found, raw_bytes, etag = self._webdav_get_bytes_with_etag(file_url, cfg=cfg, timeout=timeout)
                if found:
                    remote_notes[rel_path] = self._decode_note_bytes(raw_bytes, rel_path)
                    if etag:
                        remote_etags[rel_path] = etag
            if only_path and not remote_notes and is_safe_rel_md(only_path) and not is_safe_rel_asset(only_path) and not in_sync_subdir(only_path, excluded_subdirs):
                for alt_rel in self._webdav_find_case_variants(
                    base_url, only_path, scope=scope, cfg=cfg, timeout=timeout, excluded_subdirs=excluded_subdirs
                ):
                    alt_url = base_url + "/".join(urllib.parse.quote(p, safe="") for p in alt_rel.split("/"))
                    found, raw_bytes, etag = self._webdav_get_bytes_with_etag(alt_url, cfg=cfg, timeout=timeout)
                    if found:
                        remote_notes[alt_rel] = self._decode_note_bytes(raw_bytes, alt_rel)
                        if etag:
                            remote_etags[alt_rel] = etag
            if only_path is None:
                self._remote_preview_cache[cache_key] = (time.time(), dict(remote_notes), dict(remote_etags))
            return True, remote_notes, remote_etags, None
        except ValueError as exc:
            return False, {}, {}, str(exc)
        except Exception as exc:
            return False, {}, {}, self._tr(f"WebDAV 连接不可达: {self._error_detail(exc)}", f"WebDAV server is unreachable: {self._error_detail(exc)}")

    def _remote_has_any_content(self, protocol, cfg, target_dir="", base_url="", excluded_subdirs=()):
        if protocol in ("local_mirror", "git"):
            if not target_dir or not os.path.isdir(target_dir):
                return False
            if self._scan_mirror_files(target_dir, excluded_subdirs=excluded_subdirs):
                return True
            if cfg.get("sync_assets", True) and self._list_dir_assets(target_dir, excluded_subdirs=excluded_subdirs):
                return True
            return False
        if protocol == "webdav" and base_url:
            if self._webdav_list_files(base_url, is_safe_rel_md, cfg=cfg, excluded_subdirs=excluded_subdirs, skip_assets=True):
                return True
            if cfg.get("sync_assets", True) and self._webdav_list_files(base_url, is_safe_rel_asset, cfg=cfg, excluded_subdirs=excluded_subdirs):
                return True
        return False

    def _git_tracked_rel_paths(self, repo_root, subdir="", cfg=None, strict=False):
        """Return set of git-tracked paths relative to subdir (or repo_root).

        When strict=True (plugin-managed remote clones), raises RuntimeError if git ls-files fails
        so a corrupted index never falls back to scanning untracked/ignored leftover files.
        """
        if not repo_root or not self._has_git_marker(repo_root):
            if strict:
                raise RuntimeError(self._tr("Git 托管副本缺少仓库元数据，已中止同步", "Managed Git clone is missing repository metadata; sync aborted"))
            return None
        proc = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=repo_root,
            env=self._git_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            timeout=8,
        )
        if proc.returncode != 0:
            if strict:
                stderr_txt = (proc.stderr or proc.stdout or b"").decode("utf-8", errors="replace")
                err = self._error_detail(stderr_txt or self._tr("git ls-files 失败", "git ls-files failed"))
                raise RuntimeError(self._tr(f"无法读取 Git 托管副本的跟踪文件清单: {err}", f"Could not read tracked file list for managed Git clone: {err}"))
            return None
        sub = subdir.strip("/")
        prefix = f"{sub}/" if sub else ""
        tracked = set()
        for raw in (proc.stdout or b"").split(b"\0"):
            if not raw:
                continue
            rel = os.fsdecode(raw).replace(os.sep, "/")
            if prefix:
                if rel.startswith(prefix):
                    tracked.add(rel[len(prefix):])
            else:
                tracked.add(rel)
        return tracked

    def _plan_notebook_assets(
        self,
        protocol,
        cfg,
        nb_root,
        target_dir,
        base_url,
        base_map,
        policy,
        scope,
        local_notes,
        remote_notes,
        only_path=None,
        excluded_subdirs=(),
        tracked_remote_paths=None,
        git_tree_paths=None,
    ):
        empty = {
            "local_assets": {},
            "remote_assets": {},
            "remote_asset_etags": {},
            "remote_asset_path_map": {},
            "assets_to_push_new": [],
            "assets_to_push_overwrite": [],
            "assets_to_pull_new": [],
            "assets_to_pull_overwrite": [],
            "asset_conflicts": [],
            "assets_synced": [],
        }
        if not cfg.get("sync_assets", True) or not nb_root:
            return empty

        explicit_paths = None
        if only_path is not None:
            explicit_paths = note_asset_paths(only_path, local_notes.get(only_path, ""))
            explicit_paths.update(note_asset_paths(only_path, remote_notes.get(only_path, "")))
            if is_safe_rel_asset(only_path):
                explicit_paths.add(only_path)
            if not explicit_paths:
                return empty

        local_candidates = set(self._asset_paths_for_sync(nb_root, explicit_paths, excluded_subdirs))
        remote_candidates = set()
        if explicit_paths is None:
            if protocol == "webdav":
                remote_candidates.update(self._webdav_list_scoped(
                    base_url, is_safe_rel_asset, scope=scope, cfg=cfg, excluded_subdirs=excluded_subdirs,
                ))
            elif target_dir and os.path.isdir(target_dir):
                found_assets = self._list_dir_assets(target_dir, excluded_subdirs=excluded_subdirs)
                if tracked_remote_paths is not None:
                    found_assets = {p for p in found_assets if p in tracked_remote_paths}
                remote_candidates.update(found_assets)
        else:
            remote_candidates.update(explicit_paths)

        candidates = local_candidates | remote_candidates
        referenced = set()
        if explicit_paths is None and scope and scope != "all":
            for np, txt in local_notes.items():
                referenced.update(note_asset_paths(np, txt))
            for np, txt in remote_notes.items():
                referenced.update(note_asset_paths(np, txt))
            candidates = {p for p in candidates if self._matches_scope(p, scope)} | referenced
        if excluded_subdirs:
            candidates = {p for p in candidates if not in_sync_subdir(p, excluded_subdirs)}

        local_assets = {}
        remote_assets = {}
        remote_asset_etags = {}
        remote_asset_path_map = {}
        git_tracked_assets_folded = {}
        if git_tree_paths:
            for tp in sorted(git_tree_paths):
                if is_safe_rel_asset(tp) and not in_sync_subdir(tp, excluded_subdirs):
                    git_tracked_assets_folded.setdefault(tp.casefold(), []).append(tp)

        for rel in sorted(candidates):
            if excluded_subdirs and in_sync_subdir(rel, excluded_subdirs):
                continue
            if rel in local_candidates or rel in referenced:
                ldata = self._read_asset_file(nb_root, rel)
                if ldata is not None:
                    actual_lrel = self._resolve_actual_rel_casing(nb_root, rel)
                    local_assets[actual_lrel] = ldata
            if explicit_paths is None and rel not in remote_candidates and rel not in referenced:
                continue
            if protocol == "webdav":
                file_url = base_url + "/".join(urllib.parse.quote(p, safe="") for p in rel.split("/"))
                found, rdata, etag = self._webdav_get_bytes_with_etag(file_url, cfg=cfg)
                if found:
                    remote_assets[rel] = rdata
                    if etag:
                        remote_asset_etags[rel] = etag
                elif explicit_paths is not None or rel in referenced:
                    for alt_rel in self._webdav_find_case_variants(
                        base_url, rel, scope=scope, cfg=cfg, excluded_subdirs=excluded_subdirs, filter_fn=is_safe_rel_asset
                    ):
                        alt_url = base_url + "/".join(urllib.parse.quote(p, safe="") for p in alt_rel.split("/"))
                        found_a, rdata_a, etag_a = self._webdav_get_bytes_with_etag(alt_url, cfg=cfg)
                        if found_a:
                            remote_assets[alt_rel] = rdata_a
                            if etag_a:
                                remote_asset_etags[alt_rel] = etag_a
            elif target_dir:
                actual_rel = rel
                if git_tree_paths and rel not in git_tree_paths:
                    folded_hits = git_tracked_assets_folded.get(rel.casefold()) or []
                    if len(folded_hits) == 1:
                        actual_rel = folded_hits[0]
                if tracked_remote_paths is None or actual_rel in tracked_remote_paths:
                    rdata = self._read_asset_file(target_dir, actual_rel, excluded_subdirs=excluded_subdirs)
                    if rdata is not None:
                        if actual_rel == rel:
                            actual_rel = self._resolve_actual_rel_casing(target_dir, rel)
                        remote_assets[actual_rel] = rdata

        # Detect multi-file attachment case collisions and pair 1-to-1 case-only renamed attachments.
        local_afolded = {}
        for lp in sorted(local_assets):
            local_afolded.setdefault(lp.casefold(), []).append(lp)
        remote_afolded = {}
        for rp in sorted(remote_assets):
            remote_afolded.setdefault(rp.casefold(), []).append(rp)

        multi_remote_a = [grp for grp in remote_afolded.values() if len(grp) > 1]
        if multi_remote_a and self._dir_is_case_insensitive(nb_root, local_assets.keys()):
            pair = " / ".join(multi_remote_a[0][:2])
            raise RuntimeError(self._tr(
                f"远端存在仅大小写不同的同名附件（{pair}），当前本地磁盘不区分大小写，请先重命名其中一个",
                f"Remote contains attachments differing only in letter case ({pair}) on a case-insensitive local disk; rename one first",
            ))
        multi_local_a = [grp for grp in local_afolded.values() if len(grp) > 1]
        if multi_local_a and protocol in ("local_mirror", "git") and self._dir_is_case_insensitive(target_dir, remote_assets.keys()):
            pair = " / ".join(multi_local_a[0][:2])
            raise RuntimeError(self._tr(
                f"本地存在仅大小写不同的同名附件（{pair}），同步目标磁盘不区分大小写，请先重命名其中一个",
                f"Local notebook contains attachments differing only in letter case ({pair}) on a case-insensitive sync target; rename one first",
            ))

        for fk, l_list in local_afolded.items():
            r_list = remote_afolded.get(fk)
            if not r_list or len(l_list) != 1 or len(r_list) != 1:
                continue
            lp, rp = l_list[0], r_list[0]
            if lp == rp or lp in remote_assets or rp in local_assets:
                continue
            collides = self._paths_case_collide_on_dir(nb_root, lp, rp) or (
                protocol in ("local_mirror", "git") and self._paths_case_collide_on_dir(target_dir, lp, rp)
            )
            if collides:
                remote_asset_path_map[lp] = rp
                remote_assets[lp] = remote_assets.pop(rp)
                if rp in remote_asset_etags:
                    remote_asset_etags[lp] = remote_asset_etags.pop(rp)
                if f"asset:{lp}" not in base_map and f"asset:{rp}" in base_map:
                    base_map[f"asset:{lp}"] = base_map[f"asset:{rp}"]

        push_new = []
        push_ow = []
        pull_new = []
        pull_ow = []
        conflicts = []
        synced = []
        reserved_copies = set()

        for rel in sorted(set(local_assets.keys()) | set(remote_assets.keys())):
            ldata = local_assets.get(rel)
            rdata = remote_assets.get(rel)
            if ldata is None and rdata is None:
                continue
            if ldata == rdata:
                synced.append(rel)
                continue
            if ldata is None:
                pull_new.append(rel)
                continue
            if rdata is None:
                push_new.append(rel)
                continue

            base_key = f"asset:{rel}"
            base_hash = base_map.get(base_key)
            lhash = sha256_bytes(ldata)
            rhash = sha256_bytes(rdata)

            if base_hash is not None and lhash == base_hash and rhash != base_hash:
                pull_ow.append((rel, False))
            elif base_hash is not None and rhash == base_hash and lhash != base_hash:
                push_ow.append((rel, False))
            else:
                if policy == "remote_first":
                    pull_ow.append((rel, True))
                elif policy == "local_first":
                    push_ow.append((rel, True))
                else:
                    stem, ext = posixpath.splitext(rel)
                    fingerprint = rhash[:16]
                    attempt = 1
                    while True:
                        suffix = "" if attempt == 1 else f"-{attempt}"
                        copy_rel = f"{stem}.conflict-{fingerprint}{suffix}{ext}"
                        if copy_rel not in reserved_copies:
                            lcopy = local_assets.get(copy_rel)
                            if lcopy is None:
                                lcopy = self._read_asset_file(nb_root, copy_rel)
                            rcopy = remote_assets.get(copy_rel)
                            if rcopy is None:
                                if protocol == "webdav":
                                    copy_url = base_url + "/".join(urllib.parse.quote(p, safe="") for p in copy_rel.split("/"))
                                    found_rc, rcopy_bytes, _ = self._webdav_get_bytes_with_etag(copy_url, cfg=cfg)
                                    rcopy = rcopy_bytes if found_rc else None
                                elif target_dir:
                                    rcopy = self._read_asset_file(target_dir, copy_rel, excluded_subdirs=excluded_subdirs)
                            if lcopy in (None, rdata) and rcopy in (None, rdata):
                                reserved_copies.add(copy_rel)
                                break
                        attempt += 1
                    conflicts.append((rel, copy_rel))

        return {
            "local_assets": local_assets,
            "remote_assets": remote_assets,
            "remote_asset_etags": remote_asset_etags,
            "remote_asset_path_map": remote_asset_path_map,
            "assets_to_push_new": push_new,
            "assets_to_push_overwrite": push_ow,
            "assets_to_pull_new": pull_new,
            "assets_to_pull_overwrite": pull_ow,
            "asset_conflicts": conflicts,
            "assets_synced": synced,
        }

    def _paths_case_collide_on_dir(self, base_dir, p1, p2):
        if not base_dir or not os.path.isdir(base_dir):
            return False
        f1 = os.path.join(base_dir, *p1.split("/"))
        f2 = os.path.join(base_dir, *p2.split("/"))
        try:
            if os.path.exists(f1) and os.path.exists(f2):
                return os.path.samefile(f1, f2)
        except OSError:
            pass
        return False

    def _dir_is_case_insensitive(self, base_dir, candidate_paths=()):
        if not base_dir or not os.path.isdir(base_dir):
            return False
        for rel in candidate_paths:
            swapped = rel.swapcase()
            if swapped != rel and self._paths_case_collide_on_dir(base_dir, rel, swapped):
                return True
        try:
            for entry in os.listdir(base_dir):
                swapped = entry.swapcase()
                if swapped != entry:
                    return self._paths_case_collide_on_dir(base_dir, entry, swapped)
        except OSError:
            pass
        return sys.platform in ("darwin", "win32")

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
        remote_etags = {}
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
                ok, fetched, fetched_etags, err = self._fetch_webdav_notes(
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
                    remote_etags = fetched_etags
                else:
                    remote_inspected = False
                    remote_error = err
            else:
                cache_key = (base_url, scope, only_path or "", frozenset(excluded_subdirs))
                if cache_key in self._remote_preview_cache:
                    _, cached_notes, cached_etags = self._remote_preview_cache[cache_key]
                    remote_notes = dict(cached_notes)
                    remote_etags = dict(cached_etags)
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
            elif self._has_git_marker(repo_dir):
                remote_notes = self._scan_mirror_files(target_dir, only_path=only_path, scope=scope, excluded_subdirs=excluded_subdirs)
            else:
                remote_inspected = False
            tracked_remote_paths = None
            git_tree_paths = None
            if remote_inspected and self._is_managed_git_dir(repo_root):
                try:
                    tracked_remote_paths = self._git_tracked_rel_paths(repo_root, subdir=subdir, cfg=cfg, strict=True)
                    git_tree_paths = tracked_remote_paths
                    remote_notes = {k: v for k, v in remote_notes.items() if k in tracked_remote_paths}
                except Exception as exc:
                    remote_inspected = False
                    remote_error = self._error_detail(exc)
            elif remote_inspected and self._has_git_marker(repo_root):
                try:
                    git_tree_paths = self._git_tracked_rel_paths(repo_root, subdir=subdir, cfg=cfg, strict=False)
                except Exception:
                    git_tree_paths = None

            if remote_inspected and not remote_error and git_tree_paths:
                local_base_dir = nb_root or self.notebook_root
                tracked_folded = {}
                only_cf = only_path.casefold() if only_path else None
                sync_assets_on = bool(cfg.get("sync_assets", True))
                only_asset_cfs = set()
                if only_path is not None and sync_assets_on:
                    for ap in note_asset_paths(only_path, local_notes.get(only_path, "")):
                        only_asset_cfs.add(ap.casefold())
                    for rnp, rtxt in remote_notes.items():
                        if rnp.casefold() == only_cf:
                            for ap in note_asset_paths(rnp, rtxt):
                                only_asset_cfs.add(ap.casefold())
                    if is_safe_rel_asset(only_path):
                        only_asset_cfs.add(only_path.casefold())
                for tp in sorted(git_tree_paths):
                    if in_sync_subdir(tp, excluded_subdirs):
                        continue
                    is_md = is_safe_rel_md(tp) and not is_safe_rel_asset(tp)
                    is_as = sync_assets_on and is_safe_rel_asset(tp)
                    if not (is_md or is_as):
                        continue
                    if is_md and not self._matches_scope(tp, scope):
                        continue
                    if only_cf is not None:
                        if is_md and tp.casefold() != only_cf:
                            continue
                        if is_as and tp.casefold() not in only_asset_cfs:
                            continue
                    tracked_folded.setdefault(tp.casefold(), []).append(tp)
                multi_tracked = [grp for grp in tracked_folded.values() if len(grp) > 1]
                if multi_tracked and (
                    self._dir_is_case_insensitive(local_base_dir, local_notes.keys())
                    or self._dir_is_case_insensitive(target_dir, remote_notes.keys())
                ):
                    pair = " / ".join(multi_tracked[0][:2])
                    remote_inspected = False
                    remote_error = self._tr(
                        f"Git 远端分支存在仅大小写不同的同名文件（{pair}），当前磁盘不区分大小写，请先在 Git 仓库中重命名其中一个",
                        f"Git remote branch contains files differing only in letter case ({pair}) on a case-insensitive disk; rename one in Git first",
                    )

        aliases = [
            self._meta_key(protocol, f"{base}::{subdir}" if subdir else base, nb_key=nb_key)
            for base in target_bases
        ]
        legacy_aliases = [f"{protocol}:{base}" for base in target_bases] if not subdir else []
        base_map = self._get_base_map(meta_key, *aliases, legacy_key, *legacy_aliases)
        initialized_map = self.sync_meta.get(INITIALIZED_META_KEY)
        is_initialized = bool(
            (isinstance(initialized_map, dict) and any(initialized_map.get(k) for k in (meta_key, *aliases)))
            or len(base_map) > 0
        )
        is_first_sync = not is_initialized

        remote_nonempty_on_first_sync = False
        if remote_inspected and is_first_sync and only_path is not None:
            try:
                remote_nonempty_on_first_sync = self._remote_has_any_content(
                    protocol, cfg, target_dir=target_dir, base_url=base_url, excluded_subdirs=excluded_subdirs,
                )
            except Exception:
                remote_nonempty_on_first_sync = True

        to_push_new = []
        to_push_overwrite = []
        to_pull_new = []
        to_pull_overwrite = []
        conflicts = []
        synced = []
        reserved_conflict_paths = set()
        remote_path_map = {}

        if remote_inspected and not remote_error:
            local_base_dir = nb_root or self.notebook_root
            local_folded = {}
            for lp in sorted(local_notes):
                local_folded.setdefault(lp.casefold(), []).append(lp)
            remote_folded = {}
            for rp in sorted(remote_notes):
                remote_folded.setdefault(rp.casefold(), []).append(rp)

            # Check for multi-file case collisions against a case-insensitive filesystem.
            multi_remote = [grp for grp in remote_folded.values() if len(grp) > 1]
            if multi_remote and self._dir_is_case_insensitive(local_base_dir, local_notes.keys()):
                pair = " / ".join(multi_remote[0][:2])
                remote_inspected = False
                remote_error = self._tr(
                    f"远端存在仅大小写不同的同名笔记（{pair}），当前本地磁盘不区分大小写，请先重命名其中一个",
                    f"Remote contains notes differing only in letter case ({pair}) on a case-insensitive local disk; rename one first",
                )
            multi_local = [grp for grp in local_folded.values() if len(grp) > 1]
            if remote_inspected and multi_local and protocol in ("local_mirror", "git") and self._dir_is_case_insensitive(target_dir, remote_notes.keys()):
                pair = " / ".join(multi_local[0][:2])
                remote_inspected = False
                remote_error = self._tr(
                    f"本地存在仅大小写不同的同名笔记（{pair}），同步目标磁盘不区分大小写，请先重命名其中一个",
                    f"Local notebook contains notes differing only in letter case ({pair}) on a case-insensitive sync target; rename one first",
                )

            # Pair 1-to-1 case-only differences (e.g. draft.md locally vs DRAFT.md on macOS mirror)
            # into a single logical note so they sync cleanly instead of colliding as two new notes.
            if remote_inspected and not remote_error:
                for fk, l_list in local_folded.items():
                    r_list = remote_folded.get(fk)
                    if not r_list or len(l_list) != 1 or len(r_list) != 1:
                        continue
                    lp, rp = l_list[0], r_list[0]
                    if lp == rp or lp in remote_notes or rp in local_notes:
                        continue
                    collides = self._paths_case_collide_on_dir(local_base_dir, lp, rp) or (
                        protocol in ("local_mirror", "git") and self._paths_case_collide_on_dir(target_dir, lp, rp)
                    )
                    if collides:
                        remote_path_map[lp] = rp
                        remote_notes[lp] = remote_notes.pop(rp)
                        if rp in remote_etags:
                            remote_etags[lp] = remote_etags.pop(rp)
                        if lp not in base_map and rp in base_map:
                            base_map[lp] = base_map[rp]

        if remote_inspected and not remote_error:
            check_local_note = None
            check_remote_note = None
            if only_path is not None:
                def check_local_note(cand):
                    found_map = self._read_local_notes(bridge, only_path=cand, scope=scope, nb_root=nb_root)
                    return found_map.get(cand)
                if protocol == "webdav":
                    def check_remote_note(cand):
                        cand_url = base_url + "/".join(urllib.parse.quote(p, safe="") for p in cand.split("/"))
                        found_c, raw_c, _ = self._webdav_get_bytes_with_etag(cand_url, cfg=cfg)
                        return self._decode_note_bytes(raw_c, cand) if found_c else None
                elif target_dir:
                    def check_remote_note(cand):
                        found_map = self._scan_mirror_files(target_dir, only_path=cand, scope=scope, excluded_subdirs=excluded_subdirs)
                        if cand in found_map:
                            return found_map[cand]
                        return next(iter(found_map.values()), None)

            all_paths = sorted(set(local_notes.keys()) | set(remote_notes.keys()))
            for rel_path in all_paths:
                in_local = rel_path in local_notes
                in_remote = rel_path in remote_notes
                if in_local and not in_remote:
                    to_push_new.append(rel_path)
                elif in_remote and not in_local:
                    to_pull_new.append(rel_path)
                else:
                    action, _, _, _ = self._resolve_conflict_pair(
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
                        conflict_rel = make_unique_conflict_path(
                            rel_path,
                            remote_notes[rel_path],
                            existing_local=local_notes,
                            existing_remote=remote_notes,
                            reserved=reserved_conflict_paths,
                            check_local=check_local_note,
                            check_remote=check_remote_note,
                        )
                        conflicts.append((rel_path, conflict_rel, remote_notes[rel_path]))
                    else:
                        synced.append(rel_path)

        asset_plan = {
            "local_assets": {},
            "remote_assets": {},
            "remote_asset_etags": {},
            "remote_asset_path_map": {},
            "assets_to_push_new": [],
            "assets_to_push_overwrite": [],
            "assets_to_pull_new": [],
            "assets_to_pull_overwrite": [],
            "asset_conflicts": [],
            "assets_synced": [],
        }
        if remote_inspected and not remote_error:
            try:
                asset_plan = self._plan_notebook_assets(
                    protocol,
                    cfg,
                    nb_root or self.notebook_root,
                    target_dir,
                    base_url,
                    base_map,
                    policy,
                    scope,
                    local_notes,
                    remote_notes,
                    only_path=only_path,
                    excluded_subdirs=excluded_subdirs,
                    tracked_remote_paths=tracked_remote_paths if protocol == "git" else None,
                    git_tree_paths=git_tree_paths if protocol == "git" else None,
                )
            except Exception as exc:
                remote_inspected = False
                remote_error = self._tr(f"附件扫描失败: {self._error_detail(exc)}", f"Attachment scan failed: {self._error_detail(exc)}")

        asset_view_copies = []
        if remote_inspected and not remote_error and policy == "keep_both" and asset_plan.get("asset_conflicts"):
            planned_asset_copy_map = {rel: copy_rel for rel, copy_rel in asset_plan["asset_conflicts"]}
            for rel_path in synced:
                rtext = remote_notes.get(rel_path)
                if rtext is None:
                    continue
                rewritten = rewrite_note_asset_links(rel_path, rtext, planned_asset_copy_map)
                if rewritten != rtext:
                    conflict_rel = make_unique_conflict_path(
                        rel_path,
                        rewritten,
                        existing_local=local_notes,
                        existing_remote=remote_notes,
                        reserved=reserved_conflict_paths,
                        check_local=check_local_note,
                        check_remote=check_remote_note,
                    )
                    asset_view_copies.append((rel_path, conflict_rel, rtext))

        remote_missing = [
            p for p in base_map
            if is_safe_rel_md(p) and self._matches_scope(p, scope) and p in local_notes and p not in remote_notes
        ] if (remote_inspected and only_path is None) else (
            [only_path] if (remote_inspected and only_path is not None and only_path in base_map and only_path in local_notes and only_path not in remote_notes) else []
        )
        local_missing = [
            p for p in base_map
            if is_safe_rel_md(p) and self._matches_scope(p, scope) and p in remote_notes and p not in local_notes
        ] if (remote_inspected and only_path is None) else []

        local_hashes = {p: sha256_text(local_notes[p]) for p in sorted(local_notes)}
        remote_hashes = {p: sha256_text(remote_notes[p]) for p in sorted(remote_notes)}
        local_asset_hashes = {p: sha256_bytes(d) for p, d in sorted(asset_plan["local_assets"].items())}
        remote_asset_hashes = {p: sha256_bytes(d) for p, d in sorted(asset_plan["remote_assets"].items())}
        base_hashes = {
            p: base_map[p]
            for p in sorted(base_map)
            if p in local_notes or p in remote_notes or (p.startswith("asset:") and (p[6:] in asset_plan["local_assets"] or p[6:] in asset_plan["remote_assets"]))
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
            "conflicts": [[c[0], c[1]] for c in conflicts],
            "asset_view_copies": [[c[0], c[1]] for c in asset_view_copies],
            "assets_push_new": asset_plan["assets_to_push_new"],
            "assets_push_ow": [a[0] for a in asset_plan["assets_to_push_overwrite"]],
            "assets_pull_new": asset_plan["assets_to_pull_new"],
            "assets_pull_ow": [a[0] for a in asset_plan["assets_to_pull_overwrite"]],
            "asset_conflicts": [[a[0], a[1]] for a in asset_plan["asset_conflicts"]],
            "remote_missing": remote_missing,
            "local_missing": local_missing,
            "local_hashes": local_hashes,
            "remote_hashes": remote_hashes,
            "local_asset_hashes": local_asset_hashes,
            "remote_asset_hashes": remote_asset_hashes,
            "base_hashes": base_hashes,
            "remote_path_map": remote_path_map,
            "remote_asset_path_map": asset_plan.get("remote_asset_path_map") or {},
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
            "remote_nonempty_on_first_sync": remote_nonempty_on_first_sync,
            "local_notes": local_notes,
            "remote_notes": remote_notes,
            "remote_etags": remote_etags,
            "remote_path_map": remote_path_map,
            "remote_inspected": remote_inspected,
            "remote_error": remote_error,
            "to_push_new": to_push_new,
            "to_push_overwrite": to_push_overwrite,
            "to_pull_new": to_pull_new,
            "to_pull_overwrite": to_pull_overwrite,
            "conflicts": conflicts,
            "asset_view_copies": asset_view_copies,
            "synced": synced,
            **asset_plan,
            "remote_missing": remote_missing,
            "local_missing": local_missing,
            "policy": policy,
            "scope": scope,
            "fingerprint": sha256_text(fp_payload),
        }

    def _format_reason_item(self, item):
        if isinstance(item, str):
            return item
        kind = item.get("kind") or ""
        nb = str(item.get("nb_label") or "").strip()
        prefix = f"{nb}: " if nb else ""
        if kind == "first_sync":
            p_new = int(item.get("pull_new") or 0)
            p_ow = int(item.get("pull_ow") or 0)
            u_ow = int(item.get("push_ow") or 0)
            conf = int(item.get("conflicts") or 0)
            return prefix + self._tr(
                f"首次同步且远端已有内容（拉取 {p_new} · 覆盖本地 {p_ow} · 覆盖远端 {u_ow} · 冲突 {conf}）",
                f"The remote already contains content on first sync (pull: {p_new}, overwrite local: {p_ow}, overwrite remote: {u_ow}, conflicts: {conf})",
            )
        if kind == "first_sync_nonempty":
            return prefix + self._tr("首次同步且远端已有其他内容", "The remote already contains other notes on first sync")
        if kind == "pull_conflict":
            n = int(item.get("count") or 0)
            return prefix + self._tr(f"远端内容将覆盖本地 {n} 项冲突文件", f"Remote content will overwrite {n} conflicting local items")
        if kind == "push_conflict":
            n = int(item.get("count") or 0)
            return prefix + self._tr(f"本地内容将覆盖远端 {n} 项冲突文件", f"Local content will overwrite {n} conflicting remote items")
        if kind == "delete_guard":
            rm = int(item.get("remote_missing") or 0)
            lm = int(item.get("local_missing") or 0)
            return prefix + self._tr(
                f"触发批量缺失保护（远端缺失 {rm} 篇 / 本地缺失 {lm} 篇，阈值 {DELETE_GUARD_THRESHOLD}）",
                f"Deletion protection triggered (missing remotely: {rm}, missing locally: {lm}, limit: {DELETE_GUARD_THRESHOLD})",
            )
        if kind == "remote_missing_single":
            p = str(item.get("path") or "")
            return prefix + self._tr(
                f"已同步笔记在远端已缺失（{p}），需确认是否重新上传",
                f"Previously synced note is missing remotely ({p}); confirm before re-uploading",
            )
        if kind == "bulk_pull":
            n = int(item.get("count") or 0)
            return prefix + self._tr(
                f"将向本地批量写入 {n} 项内容（超 {DELETE_GUARD_THRESHOLD} 项）",
                f"Bulk write to local workspace: {n} items (limit: {DELETE_GUARD_THRESHOLD})",
            )
        return prefix + str(item.get("text") or self._tr("存在风险变更", "Risky changes detected"))

    def _format_sample_item(self, item):
        if isinstance(item, str):
            return item
        kind = item.get("kind") or ""
        path = str(item.get("path") or "")
        extra = str(item.get("extra") or "")
        mapping = {
            "pull_ow": (f"[覆盖本地] {path}", f"[Overwrite local] {path}"),
            "pull_upd": (f"[更新本地] {path}", f"[Update local] {path}"),
            "push_ow": (f"[覆盖远端] {path}", f"[Overwrite remote] {path}"),
            "push_upd": (f"[更新远端] {path}", f"[Update remote] {path}"),
            "conflict": (f"[冲突副本] {path} -> {extra}", f"[Conflict copy] {path} -> {extra}"),
            "pull_new": (f"[拉取] {path}", f"[Pull] {path}"),
            "push_new": (f"[推送] {path}", f"[Push] {path}"),
            "rm_miss": (f"[远端缺失] {path}", f"[Missing remotely] {path}"),
            "loc_miss": (f"[本地缺失] {path}", f"[Missing locally] {path}"),
        }
        zh, en = mapping.get(kind, (path, path))
        return self._tr(zh, en)

    def _plan_risk_metrics(self, plan):
        base_map = plan["base_map"]
        local_notes = plan["local_notes"]
        remote_notes = plan["remote_notes"]
        n_pull_new = len(plan["to_pull_new"]) + len(plan.get("assets_to_pull_new") or ())
        n_pull_total = len(plan["to_pull_overwrite"]) + len(plan.get("assets_to_pull_overwrite") or ())
        n_pull_conflict = (
            sum(base_map.get(p) != sha256_text(local_notes[p]) for p in plan["to_pull_overwrite"])
            + sum(1 for _, is_conf in (plan.get("assets_to_pull_overwrite") or ()) if is_conf)
        )
        n_push_conflict = (
            sum(base_map.get(p) != sha256_text(remote_notes[p]) for p in plan["to_push_overwrite"])
            + sum(1 for _, is_conf in (plan.get("assets_to_push_overwrite") or ()) if is_conf)
        )
        n_conf = len(plan["conflicts"]) + len(plan.get("asset_view_copies") or ()) + len(plan.get("asset_conflicts") or ())
        n_rm_miss = len(plan["remote_missing"])
        n_loc_miss = len(plan["local_missing"])
        return {
            "pull_new": n_pull_new,
            "pull_total": n_pull_total,
            "pull_conflict": n_pull_conflict,
            "push_conflict": n_push_conflict,
            "conflicts": n_conf,
            "remote_missing": n_rm_miss,
            "local_missing": n_loc_miss,
        }

    def _assess_dangerous_changes(self, plan, cfg, saved_path=None, nb_label=""):
        if not plan.get("remote_inspected"):
            return []
        items = []
        policy = plan.get("policy") or cfg.get("conflict_policy", "keep_both")
        m = self._plan_risk_metrics(plan)

        if plan["is_first_sync"]:
            if m["pull_new"] > 0 or m["pull_conflict"] > 0 or m["push_conflict"] > 0 or m["conflicts"] > 0:
                items.append({
                    "kind": "first_sync",
                    "nb_label": nb_label,
                    "pull_new": m["pull_new"],
                    "pull_ow": m["pull_conflict"],
                    "push_ow": m["push_conflict"],
                    "conflicts": m["conflicts"],
                })
            elif plan.get("remote_nonempty_on_first_sync"):
                items.append({"kind": "first_sync_nonempty", "nb_label": nb_label})
        else:
            if m["pull_conflict"] > 0 and (policy != "remote_first" or m["pull_conflict"] > DELETE_GUARD_THRESHOLD):
                items.append({"kind": "pull_conflict", "nb_label": nb_label, "count": m["pull_conflict"]})
            if m["push_conflict"] > 0 and (policy != "local_first" or m["push_conflict"] > DELETE_GUARD_THRESHOLD):
                items.append({"kind": "push_conflict", "nb_label": nb_label, "count": m["push_conflict"]})
            if saved_path is not None and cfg.get("delete_guard", True) and m["remote_missing"] > 0:
                items.append({"kind": "remote_missing_single", "nb_label": nb_label, "path": saved_path})

        if cfg.get("delete_guard", True) and (m["remote_missing"] > DELETE_GUARD_THRESHOLD or m["local_missing"] > DELETE_GUARD_THRESHOLD):
            items.append({
                "kind": "delete_guard",
                "nb_label": nb_label,
                "remote_missing": m["remote_missing"],
                "local_missing": m["local_missing"],
            })
        elif m["pull_new"] + m["pull_total"] > DELETE_GUARD_THRESHOLD:
            items.append({"kind": "bulk_pull", "nb_label": nb_label, "count": m["pull_new"] + m["pull_total"]})
        return items

    def _check_git_staged_conflicts(self, repo_root, rel_paths, cfg=None):
        """Abort before writing or committing if any planned path already has independent staged changes in Git index."""
        cleaned = sorted({p.replace("\\", "/").lstrip("/") for p in (rel_paths or []) if p})
        if not cleaned or not repo_root or not self._has_git_marker(repo_root):
            return
        if self._is_managed_git_dir(repo_root):
            return
        # On unborn repo (no HEAD yet), diff --cached --name-only compares against empty tree via ls-files --cached.
        has_head = self._run_git(["rev-parse", "--verify", "HEAD"], cwd=repo_root, cfg=cfg).returncode == 0
        if has_head:
            proc = subprocess.run(
                ["git", "--literal-pathspecs", "diff", "--cached", "--name-only", "-z", "--", *cleaned],
                cwd=repo_root,
                env=self._git_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=8,
            )
        else:
            proc = subprocess.run(
                ["git", "--literal-pathspecs", "ls-files", "--cached", "-z", "--", *cleaned],
                cwd=repo_root,
                env=self._git_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=8,
            )
        if proc.returncode != 0:
            err_txt = (proc.stderr or proc.stdout or b"").decode("utf-8", errors="replace")
            err = self._error_detail(err_txt or self._tr("git 暂存区检查失败", "git staged index check failed"))
            raise RuntimeError(self._tr(f"Git 暂存区检查失败: {err}", f"Git staged index check failed: {err}"))
        staged_hits = sorted({os.fsdecode(raw).replace("\\", "/") for raw in (proc.stdout or b"").split(b"\0") if raw})
        if staged_hits:
            sample = ", ".join(staged_hits[:3]) + ("..." if len(staged_hits) > 3 else "")
            raise RuntimeError(self._tr(
                f"Git 暂存区已有这些文件的待提交改动，请先提交或取消暂存后再同步：{sample}",
                f"Git index already has staged changes for planned sync files; commit or unstage them first: {sample}",
            ))

    def _check_git_ignored(self, repo_root, rel_paths, cfg=None):
        norm_paths = sorted({p.replace("\\", "/").lstrip("/") for p in (rel_paths or []) if p})
        if not norm_paths:
            return
        # Note: Apple Git rejects `--literal-pathspecs` with `check-ignore`; prefixing each NUL-delimited
        # relative path with `./` disables pathspec magic (e.g. `:(glob)literal.md`) portably.
        chk_input = b"\0".join(os.fsencode("./" + p) for p in norm_paths) + b"\0"
        chk = subprocess.run(
            ["git", "check-ignore", "-z", "--stdin"],
            cwd=repo_root,
            env=self._git_env(),
            input=chk_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
        )
        if chk.returncode not in (0, 1):
            err_txt = (chk.stderr or chk.stdout or b"").decode("utf-8", errors="replace")
            err = self._error_detail(err_txt or self._tr("git check-ignore 失败", "git check-ignore failed"))
            raise RuntimeError(self._tr(f"Git 忽略规则检查失败: {err}", f"Git ignore check failed: {err}"))
        ignored = []
        for raw in (chk.stdout or b"").split(b"\0"):
            if raw:
                dec = os.fsdecode(raw)
                if dec.startswith("./"):
                    dec = dec[2:]
                ignored.append(dec)
        if ignored:
            sample = ", ".join(ignored[:3]) + ("..." if len(ignored) > 3 else "")
            raise RuntimeError(self._tr(
                f"Git 仓库的忽略规则阻止了待同步文件，无法上传：{sample}",
                f"Files planned for sync are ignored by Git ignore rules: {sample}",
            ))

    def _commit_and_push_git(self, repo_root, cfg, staged_rel_paths=None, tracked_plan_paths=None, planned_blobs=None):
        # Remove any stale untracked atomic-write temp files left behind by a prior SIGKILL cancellation
        # so they can never be staged or pushed to the remote repository.
        self._cleanup_stale_temp_files(repo_root, cfg=cfg)
        branch = self._git_branch(cfg)
        cur_branch = self._git_current_branch(repo_root, cfg=cfg)
        if cur_branch != branch:
            cur_label = cur_branch or "detached HEAD"
            raise RuntimeError(self._tr(
                f"Git 工作区当前位于 {cur_label}，与目标分支 {branch} 不一致，已中止推送",
                f"Git checkout is at {cur_label} instead of {branch}; push aborted",
            ))

        written = {p.replace("\\", "/").lstrip("/") for p in (staged_rel_paths or []) if p}
        candidate_tracked = {p.replace("\\", "/").lstrip("/") for p in (tracked_plan_paths or []) if p} - written
        all_check_paths = sorted(written | candidate_tracked)
        blob_map = {k.replace("\\", "/").lstrip("/"): v for k, v in (planned_blobs or {}).items() if k}

        # Fail loudly if .gitignore / .git/info/exclude blocks any file in the sync plan.
        self._check_git_ignored(repo_root, all_check_paths, cfg=cfg)

        # Inspect HEAD and compare exact planned blobs directly against HEAD's tree so that:
        # 1. Mutable working-tree edits arriving after sync writes are NEVER committed in place of planned bytes.
        # 2. Index flags like --assume-unchanged can NEVER hide a planned write from being committed & pushed.
        # 3. Acquiring .git/index.lock while re-checking staged conflicts, updating refs/heads/<branch>, and
        #    atomically replacing .git/index makes concurrent `git add` races impossible.
        head_chk = self._run_git(["rev-parse", "--verify", "HEAD"], cwd=repo_root, cfg=cfg)
        old_head = head_chk.stdout.strip() if head_chk.returncode == 0 and head_chk.stdout.strip() else ""
        old_tree = ""
        head_entries = {}
        if old_head:
            tree_chk = self._run_git(["rev-parse", "--verify", "HEAD^{tree}"], cwd=repo_root, cfg=cfg)
            if tree_chk.returncode == 0 and tree_chk.stdout.strip():
                old_tree = tree_chk.stdout.strip()
            if all_check_paths:
                ls_proc = subprocess.run(
                    ["git", "--literal-pathspecs", "ls-tree", "-r", "-z", old_head, "--", *all_check_paths],
                    cwd=repo_root,
                    env=self._git_env(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=8,
                )
                if ls_proc.returncode != 0:
                    err_txt = (ls_proc.stderr or ls_proc.stdout or b"").decode("utf-8", errors="replace")
                    err = self._error_detail(err_txt or self._tr("git ls-tree 失败", "git ls-tree failed"))
                    raise RuntimeError(self._tr(f"Git 树检查失败: {err}", f"Git tree inspection failed: {err}"))
                for entry in (ls_proc.stdout or b"").split(b"\0"):
                    if not entry or b"\t" not in entry:
                        continue
                    meta_b, path_b = entry.split(b"\t", 1)
                    parts = meta_b.decode("ascii", errors="replace").split()
                    if len(parts) >= 3:
                        p_str = os.fsdecode(path_b).replace("\\", "/")
                        head_entries[p_str] = (parts[0], parts[2])

        use_sha1_fast = (not old_head) or (len(old_head) == 40)
        changed_entries = []  # list of (path, mode, blob_oid)
        git_env = self._git_env()
        for p in all_check_paths:
            if p in blob_map:
                raw_data = blob_map[p]
            else:
                disk_path = os.path.join(repo_root, *p.split("/"))
                if not os.path.isfile(disk_path):
                    continue
                with open(disk_path, "rb") as fh:
                    raw_data = fh.read()
            prev_mode, prev_oid = head_entries.get(p, ("100644", ""))
            mode = prev_mode if prev_mode in ("100644", "100755") else "100644"
            if use_sha1_fast and prev_oid:
                fast_oid = hashlib.sha1(f"blob {len(raw_data)}\0".encode("ascii") + raw_data).hexdigest()
                if fast_oid == prev_oid:
                    continue
            ho_proc = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                cwd=repo_root,
                env=git_env,
                input=raw_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=8,
            )
            if ho_proc.returncode != 0:
                err_txt = (ho_proc.stderr or ho_proc.stdout or b"").decode("utf-8", errors="replace")
                err = self._error_detail(err_txt or self._tr("git hash-object 失败", "git hash-object failed"))
                raise RuntimeError(self._tr(f"Git 对象写入失败: {err}", f"Git object write failed: {err}"))
            new_oid = (ho_proc.stdout or b"").decode("ascii", errors="replace").strip()
            if old_head and new_oid == prev_oid:
                continue
            changed_entries.append((p, mode, new_oid))

        changed_paths = [p for p, _, _ in changed_entries]
        if all_check_paths:
            self._check_git_staged_conflicts(repo_root, all_check_paths, cfg=cfg)

        did_commit = False
        if changed_entries:
            real_index = self._git_path(repo_root, "index", cfg=cfg)
            if not real_index:
                raise RuntimeError(self._tr("无法定位 Git 索引文件", "Could not locate Git index file"))
            index_dir = os.path.dirname(real_index)
            pid = os.getpid()
            ts_ns = time.time_ns()
            tmp_tree_idx = os.path.join(index_dir, f"block-sync-tree-{pid}-{ts_ns}.idx")
            tmp_real_idx = os.path.join(index_dir, f"block-sync-real-{pid}-{ts_ns}.idx")
            index_lock = real_index + ".lock"
            index_info_payload = b"".join(
                f"{mode} {oid}\t".encode("ascii") + os.fsencode(p) + b"\0"
                for p, mode, oid in changed_entries
            )
            try:
                # 1. Build commit tree strictly from old_tree + exact planned blobs (isolated temp index).
                tree_env = dict(git_env)
                tree_env["GIT_INDEX_FILE"] = tmp_tree_idx
                if old_tree:
                    rt_proc = subprocess.run(
                        ["git", "read-tree", old_tree],
                        cwd=repo_root,
                        env=tree_env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=8,
                    )
                    if rt_proc.returncode != 0:
                        err_txt = (rt_proc.stderr or rt_proc.stdout or b"").decode("utf-8", errors="replace")
                        raise RuntimeError(self._tr(f"Git 树初始化失败: {self._error_detail(err_txt)}", f"Git read-tree failed: {self._error_detail(err_txt)}"))
                ui_proc = subprocess.run(
                    ["git", "update-index", "-z", "--index-info"],
                    cwd=repo_root,
                    env=tree_env,
                    input=index_info_payload,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=8,
                )
                if ui_proc.returncode != 0:
                    err_txt = (ui_proc.stderr or ui_proc.stdout or b"").decode("utf-8", errors="replace")
                    raise RuntimeError(self._tr(f"Git 索引更新失败: {self._error_detail(err_txt)}", f"Git update-index failed: {self._error_detail(err_txt)}"))
                wt_proc = subprocess.run(
                    ["git", "write-tree"],
                    cwd=repo_root,
                    env=tree_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=8,
                )
                if wt_proc.returncode != 0:
                    err_txt = (wt_proc.stderr or wt_proc.stdout or b"").decode("utf-8", errors="replace")
                    raise RuntimeError(self._tr(f"Git 写入树失败: {self._error_detail(err_txt)}", f"Git write-tree failed: {self._error_detail(err_txt)}"))
                new_tree = (wt_proc.stdout or b"").decode("ascii", errors="replace").strip()

                commit_env = dict(git_env)
                commit_env["GIT_AUTHOR_NAME"] = "Block Sync"
                commit_env["GIT_AUTHOR_EMAIL"] = "sync@blockmd.local"
                commit_env["GIT_COMMITTER_NAME"] = "Block Sync"
                commit_env["GIT_COMMITTER_EMAIL"] = "sync@blockmd.local"
                ct_args = ["git", "commit-tree", new_tree, "-m", "sync: update markdown notes"]
                if old_head:
                    ct_args[3:3] = ["-p", old_head]
                ct_proc = subprocess.run(
                    ct_args,
                    cwd=repo_root,
                    env=commit_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=8,
                )
                if ct_proc.returncode != 0:
                    err_txt = (ct_proc.stderr or ct_proc.stdout or b"").decode("utf-8", errors="replace")
                    raise RuntimeError(self._tr(f"Git 提交对象创建失败: {self._error_detail(err_txt)}", f"Git commit-tree failed: {self._error_detail(err_txt)}"))
                new_commit = (ct_proc.stdout or b"").decode("ascii", errors="replace").strip()

                # 2. Acquire .git/index.lock so no concurrent `git add` can mutate the real index between
                #    our staged-conflict check, branch ref update, and atomic index replacement.
                lock_fd = None
                lock_deadline = time.monotonic() + 2.0
                while True:
                    try:
                        lock_fd = os.open(index_lock, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                        break
                    except FileExistsError:
                        if time.monotonic() >= lock_deadline:
                            raise RuntimeError(self._tr(
                                "Git 暂存区正被其他进程锁定，请稍后重试",
                                "Git index is locked by another process; retry shortly",
                            ))
                        time.sleep(0.05)

                replaced_index = False
                try:
                    # Re-check staged conflicts under index.lock (read-only against real_index).
                    self._check_git_staged_conflicts(repo_root, all_check_paths, cfg=cfg)

                    # Clone real_index (preserving any unrelated user-staged files) and update only changed_entries.
                    if os.path.isfile(real_index):
                        shutil.copyfile(real_index, tmp_real_idx)
                    real_env = dict(git_env)
                    real_env["GIT_INDEX_FILE"] = tmp_real_idx
                    ui_real = subprocess.run(
                        ["git", "update-index", "-z", "--index-info"],
                        cwd=repo_root,
                        env=real_env,
                        input=index_info_payload,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=8,
                    )
                    if ui_real.returncode != 0:
                        err_txt = (ui_real.stderr or ui_real.stdout or b"").decode("utf-8", errors="replace")
                        raise RuntimeError(self._tr(f"Git 索引同步失败: {self._error_detail(err_txt)}", f"Git index sync failed: {self._error_detail(err_txt)}"))

                    # Atomically advance refs/heads/<branch> (fails if HEAD moved concurrently).
                    ur_proc = subprocess.run(
                        ["git", "update-ref", "-m", "sync: update markdown notes", f"refs/heads/{branch}", new_commit, old_head],
                        cwd=repo_root,
                        env=commit_env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=8,
                    )
                    if ur_proc.returncode != 0:
                        err_txt = (ur_proc.stderr or ur_proc.stdout or b"").decode("utf-8", errors="replace")
                        raise RuntimeError(self._tr(f"Git 分支更新失败（可能存在并发提交）: {self._error_detail(err_txt)}", f"Git branch update failed (concurrent commit?): {self._error_detail(err_txt)}"))

                    # Atomically replace real_index via index_lock (Git's native atomic index-commit protocol).
                    with open(tmp_real_idx, "rb") as src_idx:
                        idx_bytes = src_idx.read()
                    view = memoryview(idx_bytes)
                    while view:
                        n_written = os.write(lock_fd, view)
                        view = view[n_written:]
                    os.fsync(lock_fd)
                    os.close(lock_fd)
                    lock_fd = None
                    os.replace(index_lock, real_index)
                    replaced_index = True
                finally:
                    if lock_fd is not None:
                        try:
                            os.close(lock_fd)
                        except OSError:
                            pass
                    if not replaced_index:
                        try:
                            os.unlink(index_lock)
                        except OSError:
                            pass
                did_commit = True
            finally:
                for p_tmp in (tmp_tree_idx, tmp_real_idx):
                    try:
                        os.unlink(p_tmp)
                    except OSError:
                        pass

        remote_proc = self._run_git(["remote"], cwd=repo_root, cfg=cfg)
        if remote_proc.returncode != 0:
            err = self._error_detail(remote_proc.stderr or remote_proc.stdout or self._tr("git remote 失败", "git remote failed"))
            raise RuntimeError(self._tr(f"Git 远端检查失败: {err}", f"Git remote check failed: {err}"))

        remotes = [r.strip() for r in remote_proc.stdout.splitlines() if r.strip()]
        if remotes:
            remote_name = "origin" if "origin" in remotes else remotes[0]
            head_proc = self._run_git(["rev-parse", "--verify", "HEAD"], cwd=repo_root, cfg=cfg)
            if head_proc.returncode == 0:
                head_oid = (head_proc.stdout or "").strip()
                needs_push = False
                expected_remote_oid = self._get_git_synced_branch_oid(repo_root, branch, remote_name=remote_name, cfg=cfg)
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
                    if expected_remote_oid:
                        anc_proc = self._run_git(["merge-base", "--is-ancestor", expected_remote_oid, "HEAD"], cwd=repo_root, cfg=cfg)
                        if anc_proc.returncode != 0:
                            raise RuntimeError(self._tr(
                                f"本地 Git 分支 {branch} 与远端记录分叉，为避免覆盖远端历史已中止推送",
                                f"Local Git branch {branch} diverged from last synced remote commit; push aborted",
                            ))
                        lease_arg = f"--force-with-lease=refs/heads/{branch}:{expected_remote_oid}"
                    elif old_head and not self._has_git_pending_initial(repo_root, branch, remote_name=remote_name, cfg=cfg) and self._git_branch_has_upstream_config(repo_root, branch, remote_name=remote_name, cfg=cfg):
                        raise RuntimeError(self._tr(
                            f"远端 {remote_name} 的分支 {branch} 已不存在（疑似被删除或重置），为避免未经确认重建远端历史已中止同步",
                            f"Remote {remote_name} branch {branch} no longer exists (it may have been deleted or reset); sync aborted to avoid silently recreating remote history",
                        ))
                    else:
                        if not old_head:
                            self._record_git_pending_initial(repo_root, branch, head_oid, remote_name=remote_name, cfg=cfg)
                        lease_arg = f"--force-with-lease=refs/heads/{branch}:"
                    push_proc = self._run_git_network(
                        ["push", lease_arg, "-u", remote_name, f"HEAD:refs/heads/{branch}"],
                        cwd=repo_root,
                        timeout=12,
                        cfg=cfg,
                        retries=2,
                        total_budget=22.0,
                    )
                    if push_proc.returncode != 0:
                        err = self._git_error_message(push_proc.stderr or push_proc.stdout, self._tr("push 失败", "Push failed"))
                        raise RuntimeError(self._tr(f"已提交到本地 Git，但远端推送未完成: {err}", f"Committed locally. Git push failed: {err}"))
                    self._record_git_synced_branch(repo_root, branch, head_oid, remote_name=remote_name, cfg=cfg)
                    return True
        return did_commit

    def _validate_physical_targets(self, protocol, cfg, bindings, base_root, expected_identities=None):
        if protocol not in ("local_mirror", "git") or not base_root:
            return {}, ""
        base_real = os.path.realpath(base_root)
        identities = {}
        resolved_targets = []
        for nb, sub in bindings.items():
            tdir = os.path.join(base_root, sub) if sub else base_root
            if sub and os.path.islink(tdir):
                return {}, self._tr(
                    f"笔记本「{self._notebook_label(nb)}」的同步子目录是符号链接，已中止同步",
                    f"Sync subfolder for notebook {self._notebook_label(nb)} is a symlink; sync aborted",
                )
            treal = os.path.realpath(tdir)
            if sub:
                if treal == base_real or not treal.startswith(base_real + os.sep):
                    return {}, self._tr(
                        f"笔记本「{self._notebook_label(nb)}」的同步子目录超出同步根目录，已中止同步",
                        f"Sync subfolder for notebook {self._notebook_label(nb)} resolves outside the sync root; sync aborted",
                    )
            for prev_nb, prev_sub, prev_real in resolved_targets:
                same_or_nested = treal == prev_real or (
                    bool(sub) and bool(prev_sub) and paths_overlap(treal, prev_real)
                )
                if same_or_nested:
                    return {}, self._tr(
                        f"笔记本「{self._notebook_label(prev_nb)}」与「{self._notebook_label(nb)}」的同步目标目录指向同一或嵌套物理目录，已中止同步",
                        f"Sync folders for {self._notebook_label(prev_nb)} and {self._notebook_label(nb)} resolve to the same or nested directory; sync aborted",
                    )
            lstat_id = None
            try:
                lst = os.lstat(tdir)
                lstat_id = (lst.st_dev, lst.st_ino)
            except FileNotFoundError:
                lstat_id = None
            real_stat_id = None
            try:
                rst = os.stat(treal)
                real_stat_id = (rst.st_dev, rst.st_ino)
            except FileNotFoundError:
                real_stat_id = None
            if expected_identities and nb in expected_identities:
                exp = expected_identities[nb]
                exp_real = exp.get("real")
                exp_lstat = exp.get("lstat_id")
                exp_real_stat = exp.get("real_stat_id")
                if exp_real and treal != exp_real:
                    return {}, self._tr(
                        f"笔记本「{self._notebook_label(nb)}」的同步目标目录在执行期间已变更，已中止同步",
                        f"Sync target folder for {self._notebook_label(nb)} changed during execution; sync aborted",
                    )
                if exp_lstat is not None and lstat_id != exp_lstat:
                    return {}, self._tr(
                        f"笔记本「{self._notebook_label(nb)}」的同步目标目录已被替换，已中止同步",
                        f"Sync target folder for {self._notebook_label(nb)} was replaced during execution; sync aborted",
                    )
                if exp_real_stat is not None and real_stat_id != exp_real_stat:
                    return {}, self._tr(
                        f"笔记本「{self._notebook_label(nb)}」的同步目标实体目录已被替换，已中止同步",
                        f"Physical sync target directory for {self._notebook_label(nb)} was replaced during execution; sync aborted",
                    )
            identities[nb] = {
                "sub": sub,
                "tdir": tdir,
                "real": treal,
                "lstat_id": lstat_id,
                "real_stat_id": real_stat_id,
            }
            resolved_targets.append((nb, sub, treal))
        return identities, ""

    def _apply_notebook_plan(self, bridge, plan, only_path=None, progress_state=None):
        protocol = plan["protocol"]
        cfg = plan["cfg"]
        nb_root = plan.get("nb_root") or self.notebook_root
        subdir = plan.get("subdir") or ""
        base_map = dict(plan["base_map"])
        local_notes = plan["local_notes"]
        remote_notes = plan["remote_notes"]
        remote_etags = plan.get("remote_etags") or {}
        local_assets = plan.get("local_assets") or {}
        remote_assets = plan.get("remote_assets") or {}
        remote_asset_etags = plan.get("remote_asset_etags") or {}
        target_dir = plan["target_dir"]
        base_url = plan["base_url"]
        excluded_subdirs = plan.get("excluded_subdirs") or ()
        batch_base_root = plan.get("batch_base_root") or (self._resolve_mirror_dir(cfg) if protocol == "local_mirror" else plan.get("repo_root") or "")
        batch_bindings = plan.get("batch_bindings") or {}
        target_identities = dict(plan.get("target_identities") or {})
        written_remote_paths = []
        active_target_fd = [None]

        def verify_target():
            if protocol not in ("local_mirror", "git") or not batch_base_root:
                return
            if batch_bindings:
                fresh_ids, v_err = self._validate_physical_targets(
                    protocol, cfg, batch_bindings, batch_base_root, expected_identities=target_identities,
                )
                if v_err:
                    raise RuntimeError(v_err)
                # Once target_dir exists, pin its lstat_id & real_stat_id so any later swap is caught.
                for k_nb, info in fresh_ids.items():
                    if k_nb in target_identities:
                        cur = dict(target_identities[k_nb])
                        if cur.get("lstat_id") is None and info.get("lstat_id") is not None:
                            cur["lstat_id"] = info["lstat_id"]
                        if cur.get("real_stat_id") is None and info.get("real_stat_id") is not None:
                            cur["real_stat_id"] = info["real_stat_id"]
                        target_identities[k_nb] = cur
            elif subdir and os.path.islink(target_dir):
                raise RuntimeError(self._tr(
                    f"同步目标子目录是符号链接，已中止同步：{subdir}",
                    f"Sync target subfolder is a symlink; sync aborted: {subdir}",
                ))

        remote_path_map = plan.get("remote_path_map") or {}
        remote_asset_path_map = plan.get("remote_asset_path_map") or {}
        planned_git_blobs = {}

        def record_remote_path(rel, raw_bytes=None):
            repo_rel = f"{subdir.strip('/')}/{rel}" if subdir.strip("/") else rel
            written_remote_paths.append(repo_rel)
            if raw_bytes is not None:
                planned_git_blobs[repo_rel] = bytes(raw_bytes)

        if protocol == "local_mirror":
            def write_remote_note(rel, text, expected_hash=None, create_only=False):
                target_rel = remote_path_map.get(rel, rel)
                self._write_mirror_file(
                    target_dir,
                    target_rel,
                    text,
                    expected_hash=expected_hash,
                    create_only=create_only,
                    excluded_subdirs=excluded_subdirs,
                    verify_target=verify_target,
                    root_dir_fd=active_target_fd[0],
                )
                record_remote_path(target_rel)
            def write_remote_asset(rel, data, expected_hash=None, create_only=False):
                target_rel = remote_asset_path_map.get(rel, rel)
                self._write_mirror_bytes(
                    target_dir,
                    target_rel,
                    data,
                    expected_hash=expected_hash,
                    create_only=create_only,
                    excluded_subdirs=excluded_subdirs,
                    verify_target=verify_target,
                    root_dir_fd=active_target_fd[0],
                )
                record_remote_path(target_rel)
        elif protocol == "webdav":
            root_url = self._webdav_root_url(cfg)
            sub_dir = self._resolve_webdav_dir(cfg).strip().strip("/")
            full_sub = "/".join(p for p in (sub_dir, subdir.strip("/")) if p)
            if full_sub:
                self._webdav_ensure_dir(root_url, full_sub, cfg=cfg)
            def write_remote_note(rel, text, expected_hash=None, create_only=False):
                target_rel = remote_path_map.get(rel, rel)
                self._webdav_put_text(
                    base_url,
                    target_rel,
                    text,
                    cfg=cfg,
                    expected_hash=expected_hash,
                    expected_etag=remote_etags.get(rel),
                    create_only=create_only,
                )
            def write_remote_asset(rel, data, expected_hash=None, create_only=False):
                target_rel = remote_asset_path_map.get(rel, rel)
                self._webdav_put_bytes(
                    base_url,
                    target_rel,
                    data,
                    cfg=cfg,
                    expected_hash=expected_hash,
                    expected_etag=remote_asset_etags.get(rel),
                    create_only=create_only,
                )
        else:
            def write_remote_note(rel, text, expected_hash=None, create_only=False):
                target_rel = remote_path_map.get(rel, rel)
                self._write_mirror_file(
                    target_dir,
                    target_rel,
                    text,
                    expected_hash=expected_hash,
                    create_only=create_only,
                    excluded_subdirs=excluded_subdirs,
                    verify_target=verify_target,
                    root_dir_fd=active_target_fd[0],
                )
                record_remote_path(target_rel, text.encode("utf-8"))
            def write_remote_asset(rel, data, expected_hash=None, create_only=False):
                target_rel = remote_asset_path_map.get(rel, rel)
                self._write_mirror_bytes(
                    target_dir,
                    target_rel,
                    data,
                    expected_hash=expected_hash,
                    create_only=create_only,
                    excluded_subdirs=excluded_subdirs,
                    verify_target=verify_target,
                    root_dir_fd=active_target_fd[0],
                )
                record_remote_path(target_rel, data)

        pushed = 0
        pulled = 0
        conflict_count = 0
        asset_count = 0
        prefix = f"{plan.get('nb_label')}/" if subdir else ""
        asset_copy_map = {}

        def step_progress():
            if progress_state is not None and progress_state.get("total", 0) > 0:
                progress_state["done"] += 1
                self._emit_progress(bridge, done=progress_state["done"], total=progress_state["total"])

        lock_dir = batch_base_root if protocol == "local_mirror" else (plan.get("repo_root") if protocol == "git" else "")
        try:
            with self._target_lock(lock_dir):
                if protocol in ("local_mirror", "git"):
                    verify_target()
                    os.makedirs(target_dir, exist_ok=True)
                    verify_target()
                    exp_info = target_identities.get(nb_root) or {}
                    active_target_fd[0] = self._open_verified_dir_fd(
                        target_dir,
                        expected_real=exp_info.get("real"),
                        expected_real_stat=exp_info.get("real_stat_id"),
                        disallow_symlink=bool(subdir),
                    )
                if protocol == "git" and plan.get("repo_root"):
                    sub_prefix = f"{subdir.strip('/')}/" if subdir.strip("/") else ""
                    planned_git_writes = []
                    for p in plan["to_push_new"]:
                        planned_git_writes.append(f"{sub_prefix}{remote_path_map.get(p, p)}")
                    for p in plan["to_push_overwrite"]:
                        planned_git_writes.append(f"{sub_prefix}{remote_path_map.get(p, p)}")
                    for p, cp, _ in plan["conflicts"]:
                        planned_git_writes.append(f"{sub_prefix}{remote_path_map.get(p, p)}")
                        planned_git_writes.append(f"{sub_prefix}{cp}")
                    for _, cp, _ in (plan.get("asset_view_copies") or ()):
                        planned_git_writes.append(f"{sub_prefix}{cp}")
                    for p in (plan.get("assets_to_push_new") or ()):
                        planned_git_writes.append(f"{sub_prefix}{remote_asset_path_map.get(p, p)}")
                    for p, _ in (plan.get("assets_to_push_overwrite") or ()):
                        planned_git_writes.append(f"{sub_prefix}{remote_asset_path_map.get(p, p)}")
                    for p, cp in (plan.get("asset_conflicts") or ()):
                        planned_git_writes.append(f"{sub_prefix}{remote_asset_path_map.get(p, p)}")
                        planned_git_writes.append(f"{sub_prefix}{cp}")
                    if planned_git_writes:
                        self._check_git_staged_conflicts(plan["repo_root"], planned_git_writes, cfg=cfg)
                # 1. Planned attachment sync (with conditional verification and conflict-copy mapping).
                for rel in plan.get("assets_synced") or ():
                    if rel in local_assets:
                        base_map[f"asset:{rel}"] = sha256_bytes(local_assets[rel])

                for rel in plan.get("assets_to_push_new") or ():
                    data = local_assets[rel]
                    write_remote_asset(rel, data, create_only=True)
                    base_map[f"asset:{rel}"] = sha256_bytes(data)
                    asset_count += 1
                    step_progress()

                for rel, _ in plan.get("assets_to_push_overwrite") or ():
                    data = local_assets[rel]
                    exp_hash = sha256_bytes(remote_assets[rel]) if rel in remote_assets else None
                    write_remote_asset(rel, data, expected_hash=exp_hash)
                    base_map[f"asset:{rel}"] = sha256_bytes(data)
                    asset_count += 1
                    step_progress()

                for rel in plan.get("assets_to_pull_new") or ():
                    data = remote_assets[rel]
                    self._write_mirror_bytes(nb_root, rel, data, create_only=True)
                    base_map[f"asset:{rel}"] = sha256_bytes(data)
                    asset_count += 1
                    step_progress()

                for rel, _ in plan.get("assets_to_pull_overwrite") or ():
                    data = remote_assets[rel]
                    exp_hash = sha256_bytes(local_assets[rel]) if rel in local_assets else None
                    self._write_mirror_bytes(nb_root, rel, data, expected_hash=exp_hash)
                    base_map[f"asset:{rel}"] = sha256_bytes(data)
                    asset_count += 1
                    step_progress()

                deferred_asset_overwrites = []
                for rel, copy_rel in plan.get("asset_conflicts") or ():
                    ldata = local_assets[rel]
                    rdata = remote_assets[rel]
                    rhash = sha256_bytes(rdata)
                    # Unconditionally enforce create_only on both sides so a preempted conflict copy path
                    # with different bytes aborts BEFORE overwriting the original remote asset.
                    # Defer overwriting the original remote asset until AFTER conflict notes and
                    # asset_view_copies are safely persisted so a note-write failure never orphans the copy.
                    self._write_mirror_bytes(nb_root, copy_rel, rdata, create_only=True)
                    write_remote_asset(copy_rel, rdata, create_only=True)
                    base_map[f"asset:{copy_rel}"] = rhash
                    asset_copy_map[rel] = copy_rel
                    deferred_asset_overwrites.append((rel, ldata, rhash))
                    asset_count += 1
                    step_progress()

                if asset_count > 0:
                    self._append_log(
                        self._tr(f"{prefix}同步 {asset_count} 个附件", f"{prefix}Synced attachments: {asset_count}"),
                        "成功",
                        tone="success",
                        log_key="assets_synced",
                        log_args={"prefix": prefix, "count": asset_count},
                    )

                # 2. Planned markdown notes sync.
                for rel_path in plan["synced"]:
                    base_map[rel_path] = sha256_text(local_notes[rel_path])

                for rel_path in plan["to_push_new"]:
                    text = local_notes[rel_path]
                    write_remote_note(rel_path, text, create_only=True)
                    base_map[rel_path] = sha256_text(text)
                    pushed += 1
                    self._append_log(
                        self._tr(f"推送 {prefix}{rel_path}", f"Push {prefix}{rel_path}"),
                        "成功",
                        tone="success",
                        tooltip=self._tr(f"已推送到{self._protocol_label(protocol)}", f"Pushed to {self._protocol_label(protocol)}"),
                        log_key="push_new",
                        log_args={"path": f"{prefix}{rel_path}", "protocol": protocol},
                    )
                    step_progress()

                for rel_path in plan["to_push_overwrite"]:
                    text = local_notes[rel_path]
                    exp_hash = sha256_text(remote_notes[rel_path]) if rel_path in remote_notes else None
                    is_conflict = exp_hash is not None and base_map.get(rel_path) != exp_hash
                    write_remote_note(rel_path, text, expected_hash=exp_hash)
                    base_map[rel_path] = sha256_text(text)
                    pushed += 1
                    if is_conflict:
                        self._append_log(
                            self._tr(f"本地覆盖 {prefix}{rel_path}", f"Overwrite remote: {prefix}{rel_path}"),
                            "成功",
                            tone="success",
                            tooltip=self._tr(f"本地优先覆盖{self._protocol_label(protocol)}", f"Local version took precedence on {self._protocol_label(protocol)}"),
                            log_key="push_overwrite",
                            log_args={"path": f"{prefix}{rel_path}", "protocol": protocol},
                        )
                    else:
                        self._append_log(
                            self._tr(f"更新 {prefix}{rel_path}", f"Update {prefix}{rel_path}"),
                            "成功",
                            tone="success",
                            tooltip=self._tr(f"已同步修改到{self._protocol_label(protocol)}", f"Synced changes to {self._protocol_label(protocol)}"),
                            log_key="push_update",
                            log_args={"path": f"{prefix}{rel_path}", "protocol": protocol},
                        )
                    step_progress()

                for rel_path in plan["to_pull_new"]:
                    orig_text = remote_notes[rel_path]
                    text = rewrite_note_asset_links(rel_path, orig_text, asset_copy_map)
                    self._write_local_note(bridge, rel_path, text, nb_root=nb_root)
                    if text != orig_text:
                        write_remote_note(rel_path, text, expected_hash=sha256_text(orig_text))
                    base_map[rel_path] = sha256_text(text)
                    pulled += 1
                    self._append_log(
                        self._tr(f"拉取 {prefix}{rel_path}", f"Pull {prefix}{rel_path}"),
                        "成功",
                        tone="success",
                        tooltip=self._tr(f"已从{self._protocol_label(protocol)}拉取", f"Pulled from {self._protocol_label(protocol)}"),
                        log_key="pull_new",
                        log_args={"path": f"{prefix}{rel_path}", "protocol": protocol},
                    )
                    step_progress()

                for rel_path in plan["to_pull_overwrite"]:
                    orig_text = remote_notes[rel_path]
                    text = rewrite_note_asset_links(rel_path, orig_text, asset_copy_map)
                    local_hash = sha256_text(local_notes[rel_path])
                    is_conflict = base_map.get(rel_path) != local_hash
                    self._write_local_note(
                        bridge, rel_path, text, nb_root=nb_root, expected_revision=local_hash
                    )
                    if text != orig_text:
                        write_remote_note(rel_path, text, expected_hash=sha256_text(orig_text))
                    base_map[rel_path] = sha256_text(text)
                    pulled += 1
                    if is_conflict:
                        self._append_log(
                            self._tr(f"远端覆盖 {prefix}{rel_path}", f"Overwrite local: {prefix}{rel_path}"),
                            "成功",
                            tone="success",
                            tooltip=self._tr(f"{self._protocol_label(protocol)}优先更新本地", f"Version from {self._protocol_label(protocol)} replaced the local copy"),
                            log_key="pull_overwrite",
                            log_args={"path": f"{prefix}{rel_path}", "protocol": protocol},
                        )
                    else:
                        self._append_log(
                            self._tr(f"拉取更新 {prefix}{rel_path}", f"Pull update: {prefix}{rel_path}"),
                            "成功",
                            tone="success",
                            tooltip=self._tr(f"已从{self._protocol_label(protocol)}拉取更新", f"Pulled update from {self._protocol_label(protocol)}"),
                            log_key="pull_update",
                            log_args={"path": f"{prefix}{rel_path}", "protocol": protocol},
                        )
                    step_progress()

                for rel_path, conflict_rel, remote_text in plan["conflicts"]:
                    local_text = local_notes[rel_path]
                    saved_conflict_text = rewrite_note_asset_links(conflict_rel, remote_text, asset_copy_map)
                    self._write_local_note(bridge, conflict_rel, saved_conflict_text, nb_root=nb_root)
                    write_remote_note(conflict_rel, saved_conflict_text, create_only=True)
                    write_remote_note(rel_path, local_text, expected_hash=sha256_text(remote_text))
                    base_map[rel_path] = sha256_text(local_text)
                    base_map[conflict_rel] = sha256_text(saved_conflict_text)
                    conflict_count += 1
                    self._append_log(
                        self._tr(f"冲突保留 {prefix}{rel_path}", f"Keep conflict copy: {prefix}{rel_path}"),
                        "冲突副本",
                        tone="warning",
                        tooltip=self._tr(f"已保留副本 {conflict_rel}", f"Saved a copy at {conflict_rel}"),
                        log_key="conflict_copy",
                        log_args={"path": f"{prefix}{rel_path}", "copy": conflict_rel},
                    )
                    step_progress()

                for rel_path, conflict_rel, remote_text in plan.get("asset_view_copies") or ():
                    saved_conflict_text = rewrite_note_asset_links(conflict_rel, remote_text, asset_copy_map)
                    self._write_local_note(bridge, conflict_rel, saved_conflict_text, nb_root=nb_root)
                    write_remote_note(conflict_rel, saved_conflict_text, create_only=True)
                    base_map[conflict_rel] = sha256_text(saved_conflict_text)
                    conflict_count += 1
                    self._append_log(
                        self._tr(f"冲突保留 {prefix}{rel_path}", f"Keep conflict copy: {prefix}{rel_path}"),
                        "冲突副本",
                        tone="warning",
                        tooltip=self._tr(f"已保留副本 {conflict_rel}", f"Saved a copy at {conflict_rel}"),
                        log_key="conflict_copy",
                        log_args={"path": f"{prefix}{rel_path}", "copy": conflict_rel},
                    )
                    step_progress()

                # 3. Complete deferred remote original-asset overwrites now that all conflict copies
                # and rewritten note views are safely saved on both sides.
                for rel, ldata, rhash in deferred_asset_overwrites:
                    write_remote_asset(rel, ldata, expected_hash=rhash)
                    base_map[f"asset:{rel}"] = sha256_bytes(ldata)
        except Exception:
            if protocol != "git":
                self.sync_meta[plan["meta_key"]] = base_map
                try:
                    bridge.call_host("host.storage.set", {"key": "sync_meta", "value": self.sync_meta})
                except Exception:
                    pass
            raise
        finally:
            if active_target_fd[0] is not None:
                try:
                    os.close(active_target_fd[0])
                except OSError:
                    pass
                active_target_fd[0] = None

        for lp, rp in remote_path_map.items():
            if rp != lp and lp in base_map and rp not in local_notes:
                base_map.pop(rp, None)
        for lp, rp in remote_asset_path_map.items():
            if rp != lp and f"asset:{lp}" in base_map and rp not in local_assets:
                base_map.pop(f"asset:{rp}", None)

        synced_repo_paths = []
        if protocol == "git":
            sub_prefix = f"{subdir.strip('/')}/" if subdir.strip("/") else ""
            for rel_path in plan["synced"]:
                repo_rel = f"{sub_prefix}{remote_path_map.get(rel_path, rel_path)}"
                synced_repo_paths.append(repo_rel)
                if repo_rel not in planned_git_blobs and rel_path in local_notes:
                    planned_git_blobs[repo_rel] = local_notes[rel_path].encode("utf-8")
            for rel_path in plan.get("assets_synced") or ():
                repo_rel = f"{sub_prefix}{remote_asset_path_map.get(rel_path, rel_path)}"
                synced_repo_paths.append(repo_rel)
                if repo_rel not in planned_git_blobs and rel_path in local_assets:
                    planned_git_blobs[repo_rel] = bytes(local_assets[rel_path])
        return pushed, pulled, conflict_count, asset_count, base_map, written_remote_paths, synced_repo_paths, planned_git_blobs

    def _compute_batch_plan(self, bridge, cfg, notebooks, only_path=None, inspect_remote=True, force_refresh=False):
        protocol = cfg.get("protocol", "local_mirror")
        target_display = self._target_display(cfg)
        repo_dir = None
        if protocol == "git":
            repo_dirs = self._git_repo_dirs(cfg)
            repo_dir = next((path for path in repo_dirs if self._has_git_marker(path)), repo_dirs[0])
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

        # Reject overlapping or aliased local notebooks in the same batch.
        for idx_nb, nb in enumerate(notebooks):
            for prev_nb in notebooks[:idx_nb]:
                if paths_overlap(prev_nb, nb):
                    return {
                        "cfg": dict(cfg),
                        "protocol": protocol,
                        "target_display": target_display,
                        "repo_root": prepared_repo_dir or "",
                        "plans": [],
                        "remote_error": self._tr(
                            f"笔记本「{self._notebook_label(prev_nb)}」与「{self._notebook_label(nb)}」的本地目录重叠，已中止同步",
                            f"Local folders for {self._notebook_label(prev_nb)} and {self._notebook_label(nb)} overlap; sync aborted",
                        ),
                        "fingerprint": "",
                    }

        # Validate physical target directories across ALL configured notebook bindings (not only the narrowed
        # auto-sync target) and record directory identities for post-plan TOCTOU verification during execution.
        base_root = ""
        target_identities = {}
        if protocol in ("local_mirror", "git"):
            base_root = self._resolve_mirror_dir(cfg) if protocol == "local_mirror" else (prepared_repo_dir or repo_dir)
            target_identities, phys_err = self._validate_physical_targets(protocol, cfg, bindings, base_root)
            if phys_err:
                return {
                    "cfg": dict(cfg),
                    "protocol": protocol,
                    "target_display": target_display,
                    "repo_root": prepared_repo_dir or "",
                    "plans": [],
                    "remote_error": phys_err,
                    "fingerprint": "",
                }

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
            plan["batch_base_root"] = base_root
            plan["batch_bindings"] = dict(bindings)
            plan["target_identities"] = {k: dict(v) for k, v in target_identities.items()}
            plans.append(plan)

        phys_fp = [
            [nb, info.get("real"), list(info["real_stat_id"]) if info.get("real_stat_id") is not None else None]
            for nb, info in sorted(target_identities.items())
        ]
        fp = sha256_text(json.dumps({"plans": [p["fingerprint"] for p in plans], "targets": phys_fp}, ensure_ascii=False))
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
            + len(p.get("asset_view_copies") or ())
            + len(p.get("assets_to_push_new") or ())
            + len(p.get("assets_to_push_overwrite") or ())
            + len(p.get("assets_to_pull_new") or ())
            + len(p.get("assets_to_pull_overwrite") or ())
            + len(p.get("asset_conflicts") or ())
            for p in batch["plans"]
        )
        progress_state = {"done": 0, "total": total_items} if (report_progress and total_items > 0) else None
        if progress_state is not None:
            self._emit_progress(bridge, done=0, total=total_items)

        pending_base_maps = []
        staged_git_paths = []
        tracked_git_paths = []
        planned_git_blobs = {}
        # For Git batches, check ALL planned write paths across ALL notebooks against the Git index
        # BEFORE writing any notebook so a staged-index conflict on notebook B never leaves notebook A mutated.
        if protocol == "git" and batch.get("repo_root"):
            all_planned_git_writes = []
            for plan in batch["plans"]:
                sub = (plan.get("subdir") or "").strip("/")
                sub_prefix = f"{sub}/" if sub else ""
                rpm = plan.get("remote_path_map") or {}
                rapm = plan.get("remote_asset_path_map") or {}
                asset_copy_map = {orig: cp for orig, cp in (plan.get("asset_conflicts") or ())}
                remote_notes = plan.get("remote_notes") or {}
                for p in plan["to_push_new"]:
                    all_planned_git_writes.append(f"{sub_prefix}{rpm.get(p, p)}")
                for p in plan["to_push_overwrite"]:
                    all_planned_git_writes.append(f"{sub_prefix}{rpm.get(p, p)}")
                if asset_copy_map:
                    for p in plan["to_pull_new"]:
                        orig_text = remote_notes.get(p)
                        if orig_text is not None and rewrite_note_asset_links(p, orig_text, asset_copy_map) != orig_text:
                            all_planned_git_writes.append(f"{sub_prefix}{rpm.get(p, p)}")
                    for p in plan["to_pull_overwrite"]:
                        orig_text = remote_notes.get(p)
                        if orig_text is not None and rewrite_note_asset_links(p, orig_text, asset_copy_map) != orig_text:
                            all_planned_git_writes.append(f"{sub_prefix}{rpm.get(p, p)}")
                for p, cp, _ in plan["conflicts"]:
                    all_planned_git_writes.append(f"{sub_prefix}{rpm.get(p, p)}")
                    all_planned_git_writes.append(f"{sub_prefix}{cp}")
                for _, cp, _ in (plan.get("asset_view_copies") or ()):
                    all_planned_git_writes.append(f"{sub_prefix}{cp}")
                for p in (plan.get("assets_to_push_new") or ()):
                    all_planned_git_writes.append(f"{sub_prefix}{rapm.get(p, p)}")
                for p, _ in (plan.get("assets_to_push_overwrite") or ()):
                    all_planned_git_writes.append(f"{sub_prefix}{rapm.get(p, p)}")
                for p, cp in (plan.get("asset_conflicts") or ()):
                    all_planned_git_writes.append(f"{sub_prefix}{rapm.get(p, p)}")
                    all_planned_git_writes.append(f"{sub_prefix}{cp}")
                for p in plan["synced"]:
                    all_planned_git_writes.append(f"{sub_prefix}{rpm.get(p, p)}")
                for p in (plan.get("assets_synced") or ()):
                    all_planned_git_writes.append(f"{sub_prefix}{rapm.get(p, p)}")
            if all_planned_git_writes:
                with self._target_lock(batch["repo_root"]):
                    self._check_git_ignored(batch["repo_root"], all_planned_git_writes, cfg=cfg)
                    self._check_git_staged_conflicts(batch["repo_root"], all_planned_git_writes, cfg=cfg)

        for plan in batch["plans"]:
            pushed, pulled, conflicts, assets, updated_base, written_paths, synced_paths, nb_blobs = self._apply_notebook_plan(
                bridge, plan, only_path=only_path, progress_state=progress_state
            )
            total_pushed += pushed
            total_pulled += pulled
            total_conflicts += conflicts
            total_assets += assets
            pending_base_maps.append((plan["meta_key"], updated_base))
            staged_git_paths.extend(written_paths)
            tracked_git_paths.extend(synced_paths)
            planned_git_blobs.update(nb_blobs)
            if protocol != "git":
                self.sync_meta[plan["meta_key"]] = updated_base

        did_push = False
        if protocol == "git" and batch.get("repo_root"):
            if report_progress:
                self._emit_progress(
                    bridge,
                    done=total_items if total_items > 0 else None,
                    total=total_items if total_items > 0 else None,
                    label=self._tr("推送 Git…", "Pushing Git…"),
                )
            with self._target_lock(batch["repo_root"]):
                did_push = self._commit_and_push_git(
                    batch["repo_root"],
                    cfg,
                    staged_rel_paths=staged_git_paths,
                    tracked_plan_paths=tracked_git_paths,
                    planned_blobs=planned_git_blobs,
                )
            for mk, updated_base in pending_base_maps:
                self.sync_meta[mk] = updated_base

        init_map = self.sync_meta.get(INITIALIZED_META_KEY)
        init_map = dict(init_map) if isinstance(init_map, dict) else {}
        for plan in batch["plans"]:
            init_map[plan["meta_key"]] = True
        self.sync_meta[INITIALIZED_META_KEY] = init_map

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
                self._append_log(
                    self._tr(f"{self._protocol_label(protocol)}同步", f"{self._protocol_label(protocol)} sync"),
                    "无变更",
                    tone="info",
                    tooltip=summary,
                    log_key="sync_noop",
                    log_args={"protocol": protocol},
                )
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

    def _build_pending_confirm(self, batch, reason_items):
        sample_items = []
        total_samples = 0

        def add_sample(kind, path, extra=""):
            nonlocal total_samples
            total_samples += 1
            if len(sample_items) < MAX_STORED_CONFIRM_SAMPLES:
                item = {"kind": kind, "path": path}
                if extra:
                    item["extra"] = extra
                sample_items.append(item)

        multi = len(batch["plans"]) > 1
        for plan in batch["plans"]:
            prefix = f"{plan['nb_label']}/" if multi else ""
            base_map = plan["base_map"]
            local_notes = plan["local_notes"]
            remote_notes = plan["remote_notes"]
            for p in plan["to_pull_overwrite"]:
                add_sample("pull_ow" if base_map.get(p) != sha256_text(local_notes[p]) else "pull_upd", f"{prefix}{p}")
            for p in plan["to_push_overwrite"]:
                add_sample("push_ow" if base_map.get(p) != sha256_text(remote_notes[p]) else "push_upd", f"{prefix}{p}")
            for p, cr, _ in plan["conflicts"]:
                add_sample("conflict", f"{prefix}{p}", extra=cr)
            for p, is_conf in plan.get("assets_to_pull_overwrite") or ():
                add_sample("pull_ow" if is_conf else "pull_upd", f"{prefix}{p}")
            for p, is_conf in plan.get("assets_to_push_overwrite") or ():
                add_sample("push_ow" if is_conf else "push_upd", f"{prefix}{p}")
            for p, cr in plan.get("asset_conflicts") or ():
                add_sample("conflict", f"{prefix}{p}", extra=cr)
            for p in plan["to_pull_new"]:
                add_sample("pull_new", f"{prefix}{p}")
            for p in plan.get("assets_to_pull_new") or ():
                add_sample("pull_new", f"{prefix}{p}")
            for p in plan["to_push_new"]:
                add_sample("push_new", f"{prefix}{p}")
            for p in plan.get("assets_to_push_new") or ():
                add_sample("push_new", f"{prefix}{p}")
            for p in plan["remote_missing"]:
                add_sample("rm_miss", f"{prefix}{p}")
            for p in plan["local_missing"]:
                add_sample("loc_miss", f"{prefix}{p}")

        return {
            "scope_key": self._result_key(),
            "fingerprint": batch["fingerprint"],
            "protocol": batch["protocol"],
            "target_display": sanitize_url_for_display(batch["target_display"]),
            "reason_items": list(reason_items[:30]),
            "reasons": [self._format_reason_item(r) for r in reason_items[:30]],
            "sample_items": sample_items,
            "total_samples": total_samples,
        }

    def _assess_batch_dangerous_changes(self, batch, cfg, saved_path=None):
        reason_items = []
        multi = len(batch["plans"]) > 1
        policy = cfg.get("conflict_policy", "keep_both")
        total_rm_miss = 0
        total_loc_miss = 0
        total_pull_writes = 0
        total_pull_conflicts = 0
        total_push_conflicts = 0
        has_delete_guard = False
        has_bulk_pull = False
        has_pull_conflict = False
        has_push_conflict = False

        for plan in batch["plans"]:
            nb_lbl = plan["nb_label"] if multi else ""
            nb_items = self._assess_dangerous_changes(plan, cfg, saved_path=saved_path, nb_label=nb_lbl)
            for it in nb_items:
                if it.get("kind") == "delete_guard":
                    has_delete_guard = True
                elif it.get("kind") == "bulk_pull":
                    has_bulk_pull = True
                elif it.get("kind") == "pull_conflict":
                    has_pull_conflict = True
                elif it.get("kind") == "push_conflict":
                    has_push_conflict = True
                reason_items.append(it)
            if plan.get("remote_inspected"):
                m = self._plan_risk_metrics(plan)
                total_rm_miss += m["remote_missing"]
                total_loc_miss += m["local_missing"]
                total_pull_writes += m["pull_new"] + m["pull_total"]
                if not plan["is_first_sync"]:
                    total_pull_conflicts += m["pull_conflict"]
                    total_push_conflicts += m["push_conflict"]

        if multi:
            if not has_delete_guard and cfg.get("delete_guard", True) and (
                total_rm_miss > DELETE_GUARD_THRESHOLD or total_loc_miss > DELETE_GUARD_THRESHOLD
            ):
                reason_items.append({
                    "kind": "delete_guard",
                    "nb_label": "",
                    "remote_missing": total_rm_miss,
                    "local_missing": total_loc_miss,
                })
            elif not has_bulk_pull and total_pull_writes > DELETE_GUARD_THRESHOLD:
                reason_items.append({"kind": "bulk_pull", "nb_label": "", "count": total_pull_writes})
            if not has_pull_conflict and total_pull_conflicts > DELETE_GUARD_THRESHOLD and policy == "remote_first":
                reason_items.append({"kind": "pull_conflict", "nb_label": "", "count": total_pull_conflicts})
            if not has_push_conflict and total_push_conflicts > DELETE_GUARD_THRESHOLD and policy == "local_first":
                reason_items.append({"kind": "push_conflict", "nb_label": "", "count": total_push_conflicts})

        return reason_items

    def _run_sync(self, bridge, only_path=None, only_nb_root=None, confirmed=False, approved_batch=None, report_progress=False):
        self._last_sync_outcome = "skipped"
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
            reason_items = self._assess_batch_dangerous_changes(batch, self.config, saved_path=only_path)
            if reason_items:
                self._last_sync_outcome = "pending_confirm"
                first_reason = self._format_reason_item(reason_items[0])
                if only_path is not None:
                    cta = (
                        self._tr("请前往同步页确认或重新同步", "Open Sync settings to review and confirm")
                        if self.pending_confirm
                        else self._tr("请点击立即同步确认", "Click Sync Now to confirm")
                    )
                    msg = self._tr(f"自动同步暂停（{first_reason}），{cta}", f"Auto-sync paused ({first_reason}). {cta}.")
                    self._append_log(
                        self._tr(f"自动同步暂停 ({only_path})", f"Auto-sync paused ({only_path})"),
                        "待确认",
                        tone="warning",
                        tooltip=msg,
                        log_key="auto_paused",
                        log_args={"path": only_path},
                    )
                    self._record_result("待确认", msg, protocol=protocol, target=batch["target_display"])
                    self._save_runtime(bridge)
                    self.last_status = msg
                    return msg
                self._set_pending_confirm(self._build_pending_confirm(batch, reason_items))
                msg = self._tr("检测到危险变更，请先确认后执行", "Risky changes detected. Confirm to continue.")
                self._append_log(
                    first_reason,
                    "待确认",
                    tone="warning",
                    tooltip=msg,
                    log_key="confirm_required",
                    log_args={"reason_item": reason_items[0]},
                )
                self._record_result("待确认", first_reason, protocol=protocol, target=batch["target_display"])
                self._save_runtime(bridge)
                self.last_status = msg
                return msg

        self._last_synced_notebooks = []
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

        self._last_sync_outcome = "synced"
        self._last_synced_notebooks = [p["nb_root"] for p in batch.get("plans") or () if p.get("nb_root")]
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
            log_key="test_conn",
            log_args={"protocol": protocol},
        )
        self.last_status = msg
        return bool(ok), msg

    def _confirmation_card(self):
        pending = self.pending_confirm
        reason_items = pending.get("reason_items") or []
        if reason_items:
            reason_texts = [self._format_reason_item(r) for r in reason_items]
        else:
            reason_texts = list(pending.get("reasons") or [])
        n_reasons = len(reason_texts)

        sample_items = pending.get("sample_items") or []
        if sample_items:
            sample_texts = [self._format_sample_item(s) for s in sample_items]
        else:
            sample_texts = list(pending.get("sample_lines") or [])
        total_samples = max(int(pending.get("total_samples") or 0), len(sample_texts))

        # Fit strictly within Block's 10-line preview box without silent truncation.
        max_lines = 10
        lines = []
        max_reason_lines = 4 if sample_texts else (max_lines - 1)
        if n_reasons > max_reason_lines:
            for r in reason_texts[:max_reason_lines]:
                lines.append(self._tr(f"[风险] {r}", f"[Risk] {r}"))
            lines.append(self._tr(f"… 其余 {n_reasons - max_reason_lines} 项风险", f"… {n_reasons - max_reason_lines} more risks"))
        else:
            for r in reason_texts:
                lines.append(self._tr(f"[风险] {r}", f"[Risk] {r}"))

        slots_left = max(0, max_lines - len(lines))
        if total_samples > 0 and slots_left > 0:
            if total_samples > slots_left:
                show_n = max(0, slots_left - 1)
                lines.extend(sample_texts[:show_n])
                hidden = total_samples - show_n
                lines.append(self._tr(f"… 其余 {hidden} 项变更", f"… {hidden} more changes"))
            else:
                lines.extend(sample_texts[:slots_left])

        preview = {
            "variant": "plan",
            "palette": "warm",
            "title": self._protocol_label(pending["protocol"]),
            "badge": self._tr(f"需确认 · {n_reasons} 项风险", f"Confirmation required · Risks: {n_reasons}"),
            "body": "\n".join(lines),
        }
        if pending.get("target_display"):
            preview["subtitle"] = sanitize_url_for_display(pending["target_display"])
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
            latest_state = str(last_result.get("status") or "").strip()
            if has_pending_confirm:
                status = self._tr("检测到危险变更，请确认后同步", "Risky changes detected. Confirm to sync.")
            elif latest_state in ("失败", "未连通"):
                status = self._tr("上次同步未完成，请查看记录或重试", "Last sync failed; check recent activity or retry")
            elif latest_state == "已取消":
                status = self._tr("上次同步已取消", "Last sync canceled")
            elif latest_state == "待确认":
                status = self._tr("存在待确认的同步变更，请点击立即同步", "Pending sync changes require confirmation; click Sync Now")
            elif isinstance(last_ok, dict) and last_ok.get("time"):
                sync_hm = format_hm(last_ok["time"])
                status = self._tr(f"上次同步 {sync_hm}", f"Last sync {sync_hm}")
            elif last_result.get("summary"):
                status = str(last_result["summary"])
                if self._is_en() and last_result.get("locale") != "en" and CHINESE_TEXT.search(status):
                    status = LOG_STATUS_EN.get(latest_state, "See recent sync activity for the last result")
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
                if isinstance(values, dict) and values:
                    draft_cfg = self._normalize_config(values)
                    if draft_cfg != self.config:
                        status = self._tr(
                            "同步配置有未保存修改，请先保存或点击「立即同步」重新预览",
                            "Sync settings have unsaved edits; save them or click Sync Now to review the new target",
                        )
                        self.last_status = status
                        return {
                            "ok": False,
                            "tone": "warning",
                            "page": self.build_page(cfg=draft_cfg),
                            "status": status,
                        }
                pc = self.pending_confirm
                if not pc or pc.get("scope_key") != self._result_key():
                    status = self._tr(
                        "待确认的同步计划已失效，请重新点击「立即同步」",
                        "The pending sync confirmation expired; click Sync Now to review again",
                    )
                    self.last_status = status
                    ok = False
                    tone = "warning"
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
                        reason_items = self._assess_batch_dangerous_changes(batch, self.config)
                        if reason_items:
                            self._set_pending_confirm(self._build_pending_confirm(batch, reason_items))
                            self._append_log(
                                self._format_reason_item(reason_items[0]),
                                "待确认",
                                tone="warning",
                                tooltip=self._tr(
                                    "同步计划已变化，请重新确认",
                                    "The sync plan changed. Review and confirm it again.",
                                ),
                                log_key="confirm_required",
                                log_args={"reason_item": reason_items[0]},
                            )
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
                            self._clear_pending_confirm()
                            self._append_log(
                                self._tr("同步计划已变化", "The sync plan changed"),
                                "已更新",
                                tone="info",
                                tooltip=self._tr(
                                    "原危险变更已消除，请重新同步",
                                    "The original risks are gone. Start sync again.",
                                ),
                                log_key="plan_changed",
                            )
                            self._record_result("已更新", self._tr(
                                "同步计划已变化，请重新同步",
                                "The sync plan changed. Start sync again.",
                            ), protocol=batch["protocol"], target=batch["target_display"])
                            self._save_runtime(bridge)
                            status = self._tr("同步计划已变化，请重新同步", "The sync plan changed. Start sync again.")
                            self.last_status = status
                            ok = False
                            tone = "info"
                    else:
                        err = self._target_error(self.config)
                        if err or not self._selected_notebooks(self.config):
                            self._clear_pending_confirm(bridge)
                            status = err or self._tr("请至少选择一个笔记本", "Select at least one notebook")
                            self.last_status = status
                            ok = False
                            tone = "danger"
                        else:
                            status = self._run_sync(bridge, confirmed=True, approved_batch=batch, report_progress=True)
                            self._clear_pending_confirm(bridge)
                            ok = True
                            tone = "success"
            elif action_id == "cancel_confirm":
                self._clear_pending_confirm()
                self._append_log(
                    self._tr("危险变更同步", "Sync with risky changes"),
                    "已取消",
                    tone="info",
                    tooltip=self._tr("用户已取消本次同步", "The user canceled this sync"),
                    log_key="sync_canceled",
                )
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
            if action_id in ("sync_now", "confirm_sync", "confirm_sync_card") and ok and tone == "success":
                res["synced_notebooks"] = list(self._last_synced_notebooks)
            return res

        if method == "plugin.event":
            event_name = str(params.get("event") or "")
            rel_path = str(params.get("path") or "").replace("\\", "/")
            event_nb = self._norm_nb_path(params.get("notebook_root") or self.notebook_root)
            outcome = "skipped"
            if event_name == "note.saved" and self.config["auto_sync"] and is_safe_rel_md(rel_path) and self._matches_scope(rel_path):
                self._refresh_known_notebooks(bridge)
                if not self._target_error(self.config):
                    selected = self._selected_notebooks(self.config)
                    if not self.supports_multi_notebook or (event_nb and event_nb in selected):
                        self._run_sync(bridge, only_path=rel_path, only_nb_root=event_nb or None)
                        outcome = getattr(self, "_last_sync_outcome", "synced")
            return {"handled": True, "outcome": outcome}

        if method == "plugin.shutdown":
            return {"ok": True}

        raise RuntimeError(f"unsupported method: {method}")


def main():
    plugin = SyncPlugin()
    HostBridge().serve(plugin.handle, plugin._localize_error)


if __name__ == "__main__":
    main()
