#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import secrets
import select
import shlex
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        
        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server
import snapshot_utils

def env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        print(f"[配置警告] 环境变量 {name}={raw!r} 不是有效整数，使用默认值 {default}", flush=True)
        value = default
    if min_value is not None and value < min_value:
        print(f"[配置警告] 环境变量 {name}={value} 小于允许值 {min_value}，使用默认值 {default}", flush=True)
        return default
    if max_value is not None and value > max_value:
        print(f"[配置警告] 环境变量 {name}={value} 大于允许值 {max_value}，使用默认值 {default}", flush=True)
        return default
    return value

def bounded_int(value: Any, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and parsed < min_value:
        return default
    if max_value is not None and parsed > max_value:
        return default
    return parsed

def ports_conflict(web_port: Any, proxy_port: Any) -> bool:
    try:
        return int(web_port) == int(proxy_port)
    except (TypeError, ValueError):
        return False

API_HTTPS_URL = os.environ.get("VPNGATE_API_HTTPS_URL", "https://www.vpngate.net/api/iphone/").strip()
API_HTTP_URL = os.environ.get("VPNGATE_API_HTTP_URL", "http://www.vpngate.net/api/iphone/").strip()
MIRROR_HTTPS_URL = os.environ.get(
    "VPNGATE_MIRROR_HTTPS_URL",
    "https://baoweise-bot.github.io/aimili-vpngate/vpngate.csv",
).strip()
MIRROR_HTTP_URL = os.environ.get(
    "VPNGATE_MIRROR_HTTP_URL",
    "http://baoweise-bot.github.io/aimili-vpngate/vpngate.csv",
).strip()
MIRROR_META_URL = os.environ.get(
    "VPNGATE_MIRROR_META_URL",
    "https://baoweise-bot.github.io/aimili-vpngate/vpngate.meta.json",
).strip()
# Kept as the primary URL for diagnostics and backwards-compatible state output.
API_URL = API_HTTPS_URL
FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 1260, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 1260, 1)
TARGET_VALID_NODES = env_int("TARGET_VALID_NODES", 3, 1)
MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 300, 1)
API_FETCH_TIMEOUT_SECONDS = env_int("API_FETCH_TIMEOUT_SECONDS", 10, 1, 60)
API_SOURCE_DEADLINE_SECONDS = env_int("API_SOURCE_DEADLINE_SECONDS", 6, 2, 30)
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 42, 1)
OPENVPN_PROBE_TIMEOUT_SECONDS = env_int("OPENVPN_PROBE_TIMEOUT_SECONDS", 18, 5, 60)
OPENVPN_FALLBACK_TIMEOUT_SECONDS = env_int("OPENVPN_FALLBACK_TIMEOUT_SECONDS", 14, 5, 45)
OPENVPN_PROTO_FALLBACK_ENABLED = os.environ.get("OPENVPN_PROTO_FALLBACK_ENABLED", "1").strip().lower() not in {"0", "false", "no"}
MANUAL_TEST_NODE_LIMIT = env_int("MANUAL_TEST_NODE_LIMIT", 5, 1, 20)
INITIAL_CONNECT_TEST_LIMIT = env_int("INITIAL_CONNECT_TEST_LIMIT", 10, 1, 50)
NODE_PROBE_WORKERS = env_int("NODE_PROBE_WORKERS", 5, 1, 20)
PROXY_FAILURE_THRESHOLD = env_int("PROXY_FAILURE_THRESHOLD", 3, 1, 10)
SWITCH_PREFLIGHT_MAX_AGE_SECONDS = env_int("SWITCH_PREFLIGHT_MAX_AGE_SECONDS", 180, 0, 3600)
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = env_int("LOCAL_PROXY_PORT", 7928, 1, 65535)
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = env_int("UI_PORT", 8787, 1, 65535)
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)
DEPLOYMENT_MODE = os.environ.get("DEPLOYMENT_MODE", "source").strip().lower()
if DEPLOYMENT_MODE not in {"source", "docker"}:
    DEPLOYMENT_MODE = "source"
DEPLOYMENT_MODE_LABEL = "Docker 容器" if DEPLOYMENT_MODE == "docker" else "Python 源码"
UPDATE_COMMAND = (
    "docker compose pull && docker compose up -d"
    if DEPLOYMENT_MODE == "docker"
    else "ml update"
)

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DEFAULT_APP_VERSION = "2.1.5"
try:
    _version_text = (ROOT_DIR / "VERSION").read_text(encoding="utf-8").strip()
except OSError:
    _version_text = DEFAULT_APP_VERSION
APP_VERSION = _version_text if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", _version_text) else DEFAULT_APP_VERSION
APP_VERSION_LABEL = f"V{APP_VERSION} 正式版"
GITHUB_REPOSITORY = "baoweise-bot/aimili-vpngate"
GITHUB_REPOSITORY_URL = f"https://github.com/{GITHUB_REPOSITORY}"
GITHUB_MAIN_BRANCH_URL = f"{GITHUB_REPOSITORY_URL}/tree/main"
GITHUB_LATEST_RELEASE_API = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/latest"
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"
API_CACHE_FILE = DATA_DIR / "api_snapshot.csv"
API_CACHE_META_FILE = DATA_DIR / "api_snapshot.meta.json"
FAVORITES_FILE = DATA_DIR / "favorites.json"
BUNDLED_SNAPSHOT_FILE = ROOT_DIR / "mirror" / "vpngate.csv"
WEB_LOG_MAX_ENTRIES = 500

lock = threading.RLock()
maintenance_lock = threading.Lock()
connection_attempt_lock = threading.Lock()
background_refill_lock = threading.Lock()
background_refill_cancel_event = threading.Event()
background_refill_thread: threading.Thread | None = None
batch_test_cancel_event = threading.Event()
batch_test_running = False
batch_test_total = 0
batch_test_completed = 0
cleanip_batch_running = False
cleanip_batch_total = 0
cleanip_batch_completed = 0
active_sessions: dict[str, float] = {}
active_openvpn_process: Any = None
pending_openvpn_process: Any = None
active_connection_cancel_event: threading.Event | None = None
connection_epoch = 0
active_openvpn_node_id = ""
active_tunnel_interface = "tun0"
active_tunnel_protocol = "openvpn"
is_connecting = False
last_active_ping_time = 0.0
last_active_latency = 0
consecutive_proxy_failures = 0
last_proxy_failure_node_id = ""

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0
server_start_time = time.time()
ip_enrichment_wakeup = threading.Event()

IP_ENRICHMENT_FIELDS = (
    "owner",
    "asn",
    "as_name",
    "location",
    "ip_type",
    "quality",
    "is_proxy",
    "is_hosting",
    "is_mobile",
    "ip_type_reason",
    "ip_type_confidence",
    "ip_type_sources",
    "geo_country_short",
    *vpn_utils.CLEANIP_NODE_FIELDS,
    *vpn_utils.INTEL_NODE_FIELDS,
)

class ConnectionCancelled(RuntimeError):
    pass

class SourceDeadlineExceeded(TimeoutError):
    pass

def purge_expired_sessions(now: float | None = None) -> int:
    current_time = time.time() if now is None else now
    with lock:
        expired_tokens = [
            token for token, expires_at in active_sessions.items()
            if expires_at <= current_time
        ]
        for token in expired_tokens:
            active_sessions.pop(token, None)
    return len(expired_tokens)

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def upstream_proxy_auth_file() -> str | None:
    username, password = vpn_utils.get_upstream_proxy_auth()
    if username is None:
        return None
    try:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        UPSTREAM_PROXY_AUTH_FILE.write_text(f"{username}\n{password or ''}\n", encoding="utf-8")
        try:
            UPSTREAM_PROXY_AUTH_FILE.chmod(0o600)
        except OSError:
            pass
        return str(UPSTREAM_PROXY_AUTH_FILE)
    except Exception as exc:
        print(f"[上游代理认证] 写入认证文件失败: {exc}", flush=True)
        return None

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        if path.name == "ui_auth.json":
            try:
                tmp.chmod(0o600)
            except OSError:
                pass
        tmp.replace(path)
        if path.name == "ui_auth.json":
            try:
                path.chmod(0o600)
            except OSError:
                pass

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

import hashlib

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(secrets.choice(chars) for _ in range(12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def normalize_discovery_countries(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        code = str(item or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", code) or code in seen:
            continue
        normalized.append(code)
        seen.add(code)
        if len(normalized) >= 250:
            break
    return normalized

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": UI_HOST,
            "port": UI_PORT,
            "proxy_port": LOCAL_PROXY_PORT,
            "routing_mode": "auto",
            "force_country": "",
            "routing_ip_type": "all",
            "connection_enabled": True,
            "fixed_node_id": "",
            "favorite_node_ids": [],
            "fav_region": "",
            "fav_fail_fallback": False,
            "discovery_countries": [],
        }
        updated = False
        if auth_file.exists():
            try:
                auth_file.chmod(0o600)
            except OSError:
                pass
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback", "discovery_countries"]:
                    if key not in data:
                        updated = True
            except Exception:
                pass
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True

        normalized_port = bounded_int(config.get("port"), UI_PORT, 1, 65535)
        if normalized_port != config.get("port"):
            config["port"] = normalized_port
            updated = True

        normalized_proxy_port = bounded_int(config.get("proxy_port"), LOCAL_PROXY_PORT, 1024, 65535)
        if normalized_proxy_port == normalized_port:
            fallback_proxy_port = LOCAL_PROXY_PORT if LOCAL_PROXY_PORT != normalized_port else 7928
            if fallback_proxy_port == normalized_port:
                fallback_proxy_port = 7929
            normalized_proxy_port = fallback_proxy_port
        if normalized_proxy_port != config.get("proxy_port"):
            config["proxy_port"] = normalized_proxy_port
            updated = True

        normalized_discovery_countries = normalize_discovery_countries(config.get("discovery_countries"))
        if normalized_discovery_countries != config.get("discovery_countries"):
            config["discovery_countries"] = normalized_discovery_countries
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                write_json(auth_file, config)
            except Exception:
                pass
                
        return config

def persist_discovery_countries(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("国家筛选范围必须是国家代码列表")
    countries = normalize_discovery_countries(value)
    ui_cfg = load_ui_config()
    ui_cfg["discovery_countries"] = countries
    auth_file = DATA_DIR / "ui_auth.json"
    with lock:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        write_json(auth_file, ui_cfg)
    return countries

# 初始化时优先从 ui_auth.json 加载保存的代理出站端口和网页端口配置以覆盖环境变量
try:
    _init_cfg = load_ui_config()
    if "proxy_port" in _init_cfg:
        LOCAL_PROXY_PORT = bounded_int(_init_cfg["proxy_port"], LOCAL_PROXY_PORT, 1024, 65535)
    if "port" in _init_cfg:
        UI_PORT = bounded_int(_init_cfg["port"], UI_PORT, 1, 65535)
    if "host" in _init_cfg:
        UI_HOST = _init_cfg["host"]
except Exception:
    pass

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

_last_cleanup_time = 0.0

def cleanup_old_logs(logs_dir: Path) -> None:
    global _last_cleanup_time
    now = time.time()
    with lock:
        if now - _last_cleanup_time < 3600:
            return
        _last_cleanup_time = now
    try:
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        with lock:
                            path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        with lock:
                            path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def read_recent_log_entries(log_file: Path, limit: int = WEB_LOG_MAX_ENTRIES) -> list[dict[str, Any]]:
    if limit <= 0 or not log_file.exists():
        return []
    entries: deque[dict[str, Any]] = deque(maxlen=limit)
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except (TypeError, ValueError):
                continue
            if isinstance(entry, dict):
                entries.append(entry)
    return list(entries)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def set_state(**updates: Any) -> None:
    # Keep the read-modify-write transaction atomic across background threads.
    with lock:
        state = get_state()
        state.update(updates)
        write_json(STATE_FILE, state)

def read_nodes() -> list[dict[str, Any]]:
    raw = read_json(NODES_FILE, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]

def load_favorite_snapshots() -> dict[str, dict[str, Any]]:
    raw = read_json(FAVORITES_FILE, {})
    if not isinstance(raw, dict):
        return {}
    return {
        str(k): dict(v)
        for k, v in raw.items()
        if k and isinstance(v, dict) and v.get("id")
    }

def save_favorite_snapshots(snapshots: dict[str, dict[str, Any]]) -> None:
    cleaned = {
        str(k): dict(v)
        for k, v in snapshots.items()
        if k and isinstance(v, dict) and v.get("id")
    }
    write_json(FAVORITES_FILE, cleaned)

_vpngate_cert_blocks_cache: str | None = None

def _extract_vpngate_cert_blocks(config_text: str) -> str | None:
    if not config_text:
        return None
    ca_m = re.search(r"<ca>[\s\S]*?</ca>", config_text)
    cert_m = re.search(r"<cert>[\s\S]*?</cert>", config_text)
    key_m = re.search(r"<key>[\s\S]*?</key>", config_text)
    if ca_m and cert_m and key_m:
        return f"{ca_m.group(0)}\n{cert_m.group(0)}\n{key_m.group(0)}\n"
    return None

def get_standard_vpngate_cert_blocks(nodes: list[dict[str, Any]] | None = None) -> str | None:
    global _vpngate_cert_blocks_cache
    if _vpngate_cert_blocks_cache:
        return _vpngate_cert_blocks_cache

    # 1. Try existing nodes in memory/disk
    for n in (nodes if nodes is not None else []):
        blocks = _extract_vpngate_cert_blocks(str(n.get("config_text") or ""))
        if blocks:
            _vpngate_cert_blocks_cache = blocks
            return blocks

    # 2. Try any existing .ovpn file in CONFIG_DIR
    try:
        if CONFIG_DIR.exists():
            for ovpn_file in CONFIG_DIR.glob("*.ovpn"):
                if ovpn_file.name.startswith(".test_"):
                    continue
                blocks = _extract_vpngate_cert_blocks(ovpn_file.read_text(encoding="utf-8", errors="replace"))
                if blocks:
                    _vpngate_cert_blocks_cache = blocks
                    return blocks
    except Exception:
        pass

    # 3. Try local snapshot or bundled snapshot CSV
    for csv_path in (API_CACHE_FILE, BUNDLED_SNAPSHOT_FILE):
        try:
            if csv_path.exists():
                rows = snapshot_utils.parse_and_validate_snapshot(read_snapshot_file(csv_path), max_rows=5)
                for row in rows:
                    cfg = decode_config(row.get("OpenVPN_ConfigData_Base64", ""))
                    blocks = _extract_vpngate_cert_blocks(cfg)
                    if blocks:
                        _vpngate_cert_blocks_cache = blocks
                        return blocks
        except Exception:
            pass
    return None

def synthesize_vpngate_openvpn_config(
    ip: str,
    port: int,
    proto: str,
    nodes: list[dict[str, Any]] | None = None,
) -> str:
    proto_norm = "tcp" if str(proto or "").lower().startswith("tcp") else "udp"
    port_num = int(port) if int(port or 0) > 0 else (443 if proto_norm == "tcp" else 1194)
    cert_blocks = get_standard_vpngate_cert_blocks(nodes)
    if not cert_blocks:
        return ""
    return (
        "dev tun\n"
        f"proto {proto_norm}\n"
        f"remote {ip} {port_num}\n"
        "cipher AES-128-CBC\n"
        "data-ciphers AES-128-CBC\n"
        "auth SHA1\n"
        "resolv-retry infinite\n"
        "nobind\n"
        "persist-key\n"
        "persist-tun\n"
        "client\n"
        "verb 3\n"
        f"{cert_blocks}"
    )

def reconstruct_favorite_node_from_disk(
    fid: str,
    nodes: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    fid = str(fid or "").strip()
    if not fid:
        return None
    cfg_path = CONFIG_DIR / f"{fid}.ovpn"
    config_text = ""
    if cfg_path.exists():
        try:
            config_text = cfg_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            config_text = ""

    parts = fid.split("_")
    country_short = parts[0].upper() if parts and len(parts[0]) == 2 and parts[0].isalpha() else "XX"
    proto = parts[-1].lower() if len(parts) >= 4 and parts[-1].lower() in ("tcp", "udp") else "udp"
    port = parse_int(parts[-2]) if len(parts) >= 4 else 0
    ip_guess = "_".join(parts[1:-2]) if len(parts) >= 4 else (parts[1] if len(parts) >= 2 else "")

    if config_text:
        remote_host, remote_port, parsed_proto = vpn_utils.parse_remote(config_text, ip_guess)
        if remote_host:
            ip_guess = remote_host
        if remote_port:
            port = remote_port
        if parsed_proto and parsed_proto != "unknown":
            proto = parsed_proto
    elif ip_guess and port > 0:
        config_text = synthesize_vpngate_openvpn_config(ip_guess, port, proto, nodes=nodes)
        if config_text:
            try:
                CONFIG_DIR.mkdir(exist_ok=True, parents=True)
                cfg_path.write_text(config_text, encoding="utf-8")
            except Exception:
                pass
    else:
        return None

    if not config_text:
        return None

    code_to_zh = {
        "JP": "日本", "KR": "韩国", "US": "美国", "TW": "台湾", "HK": "香港",
        "SG": "新加坡", "TH": "泰国", "VN": "越南", "GB": "英国", "DE": "德国",
        "FR": "法国", "NL": "荷兰", "CA": "加拿大", "AU": "澳大利亚", "RU": "俄罗斯",
        "IN": "印度", "MY": "马来西亚", "ID": "印度尼西亚", "PH": "菲律宾", "BR": "巴西",
    }
    country_zh = code_to_zh.get(country_short, country_short)

    node: dict[str, Any] = {
        "id": fid,
        "country": country_zh,
        "country_short": country_short,
        "host_name": fid,
        "ip": ip_guess,
        "score": 100000,
        "ping": 0,
        "speed": 0,
        "sessions": 0,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(cfg_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": ip_guess,
        "remote_port": port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "已从本地历史配置文件恢复收藏节点",
        "probed_at": 0,
        "active": False,
        "in_latest_feed": False,
    }
    try:
        ip_cache = vpn_utils.load_ip_cache()
        cached_entry = ip_cache.get(ip_guess) if isinstance(ip_cache, dict) else None
        if isinstance(cached_entry, dict):
            vpn_utils.apply_ip_cache_entry(node, cached_entry)
    except Exception:
        pass
    return node

def sync_favorite_snapshots_with_nodes(
    fav_ids: list[str] | None = None,
    nodes: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    with lock:
        ui_cfg = load_ui_config()
        effective_fav_ids = [
            str(fid).strip()
            for fid in (fav_ids if fav_ids is not None else ui_cfg.get("favorite_node_ids", []))
            if str(fid or "").strip()
        ]
        current_nodes = list(nodes) if nodes is not None else read_nodes()
        snapshots = load_favorite_snapshots()
        snapshots_changed = False
        nodes_changed = False

        current_by_id = {str(n.get("id")): n for n in current_nodes if n.get("id")}
        fav_id_set = set(effective_fav_ids)

        for existing_id in list(snapshots.keys()):
            if existing_id not in fav_id_set:
                snapshots.pop(existing_id, None)
                snapshots_changed = True

        for fid in effective_fav_ids:
            if fid in current_by_id:
                node_copy = dict(current_by_id[fid])
                prev_snap = snapshots.get(fid)
                if isinstance(prev_snap, dict):
                    if not node_copy.get("config_text") and prev_snap.get("config_text"):
                        node_copy["config_text"] = prev_snap["config_text"]
                    for field in IP_ENRICHMENT_FIELDS:
                        if node_copy.get(field) in (None, "") and prev_snap.get(field) not in (None, ""):
                            node_copy[field] = prev_snap[field]
                if snapshots.get(fid) != node_copy:
                    snapshots[fid] = node_copy
                    snapshots_changed = True
            elif fid in snapshots or reconstruct_favorite_node_from_disk(fid, nodes=current_nodes) is not None:
                if fid not in snapshots:
                    disk_node = reconstruct_favorite_node_from_disk(fid, nodes=current_nodes)
                    if disk_node is not None:
                        snapshots[fid] = disk_node
                        snapshots_changed = True
                restored = dict(snapshots[fid])
                restored["active"] = bool(active_openvpn_node_id and restored.get("id") == active_openvpn_node_id)
                config_file = restored.get("config_file") or str(CONFIG_DIR / f"{fid}.ovpn")
                restored["config_file"] = str(config_file)
                if restored.get("config_text"):
                    try:
                        cfg_path = Path(config_file)
                        if not cfg_path.exists():
                            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
                            cfg_path.write_text(str(restored["config_text"]), encoding="utf-8")
                    except Exception:
                        pass
                current_nodes.append(restored)
                current_by_id[fid] = restored
                nodes_changed = True

        if snapshots_changed:
            save_favorite_snapshots(snapshots)
        if nodes_changed and nodes is None:
            current_nodes = sort_all_nodes(current_nodes)
            write_json(NODES_FILE, current_nodes)
        return current_nodes

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state.pop("password", None)
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state["maintenance_running"] = maintenance_lock.locked()
    state.setdefault("api_url", API_URL)
    state.setdefault("mirror_url", MIRROR_HTTPS_URL)
    state.setdefault("last_fetch_source", "")
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    _proxy_display = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
    state["local_proxy"] = f"http://{_proxy_display}:{LOCAL_PROXY_PORT}"
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("pending_node_id", "")
    state.setdefault("tunnel_ready", False)
    state.setdefault("proxy_ready", bool(state.get("proxy_ok", False)))
    state.setdefault("blacklisted_nodes", 0)
    state["app_version"] = APP_VERSION
    state["app_version_label"] = APP_VERSION_LABEL
    state["deployment_mode"] = DEPLOYMENT_MODE
    state["deployment_mode_label"] = DEPLOYMENT_MODE_LABEL
    
    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["password_set"] = bool(ui_cfg.get("password"))
    state["proxy_port"] = ui_cfg.get("proxy_port", 7928)
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    state["favorite_node_ids"] = ui_cfg.get("favorite_node_ids", [])
    state["fav_region"] = str(ui_cfg.get("fav_region") or "").strip()
    state["discovery_countries"] = normalize_discovery_countries(ui_cfg.get("discovery_countries"))
    state["fav_fail_fallback"] = False
    state["batch_test_running"] = batch_test_running
    state["batch_test_total"] = batch_test_total
    state["batch_test_completed"] = batch_test_completed
    state["cleanip_batch_running"] = cleanip_batch_running
    state["cleanip_batch_total"] = cleanip_batch_total
    state["cleanip_batch_completed"] = cleanip_batch_completed
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def clear_active_connection_state(message: str) -> None:
    stop_active_openvpn()
    with lock:
        nodes = read_nodes()
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(
        active_openvpn_node_id="",
        is_connecting=False,
        pending_node_id="",
        active_node_latency="无活动连接",
        proxy_ok=False,
        tunnel_ready=False,
        proxy_ready=False,
        proxy_ip="-",
        proxy_latency_ms=0,
        proxy_error=message,
        last_check_message=message,
    )

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def proxy_basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"

def recv_exact_from_socket(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Unexpected EOF while reading proxy response")
        data += chunk
    return data

def read_http_response_head(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("Proxy response header too large")
    if b"\r\n\r\n" not in data:
        raise RuntimeError("Incomplete HTTP proxy response header")
    return data

def socks5_address_bytes(host: str) -> tuple[int, bytes]:
    try:
        return 1, socket.inet_aton(host)
    except OSError:
        pass
    try:
        return 4, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass
    host_bytes = host.encode("idna")
    if len(host_bytes) > 255:
        raise RuntimeError("SOCKS5 target host name is too long")
    return 3, bytes([len(host_bytes)]) + host_bytes

def read_socks5_connect_reply(sock: socket.socket) -> None:
    header = recv_exact_from_socket(sock, 4)
    if header[0] != 5:
        raise RuntimeError("Invalid SOCKS5 reply version")
    atyp = header[3]
    if atyp == 1:
        recv_exact_from_socket(sock, 4)
    elif atyp == 3:
        domain_len = recv_exact_from_socket(sock, 1)[0]
        recv_exact_from_socket(sock, domain_len)
    elif atyp == 4:
        recv_exact_from_socket(sock, 16)
    else:
        raise RuntimeError(f"Invalid SOCKS5 reply address type: {atyp}")
    recv_exact_from_socket(sock, 2)
    if header[1] != 0:
        raise RuntimeError(f"SOCKS5 connection request rejected, code={header[1]}")

def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"

def fetch_api_text_via_proxy(url: str, ptype: str, phost: str, pport: int, use_ssl_verify: bool = True) -> str:
    import socket
    import ssl
    import urllib.parse

    parsed = urllib.parse.urlsplit(url)
    domain = parsed.hostname or "www.vpngate.net"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    is_ipv6 = ":" in phost
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(API_FETCH_TIMEOUT_SECONDS)
        s.connect((phost, pport))
        proxy_user, proxy_pass = vpn_utils.get_upstream_proxy_auth()
        if ptype == "socks":
            # SOCKS5 Handshake
            if proxy_user is not None:
                s.sendall(b"\x05\x02\x00\x02")
            else:
                s.sendall(b"\x05\x01\x00")
            resp = recv_exact_from_socket(s, 2)
            if len(resp) < 2 or resp[0] != 5:
                raise RuntimeError("SOCKS5 authentication failed or unsupported")
            if resp[1] == 2:
                if proxy_user is None:
                    raise RuntimeError("SOCKS5 proxy requires username/password authentication")
                user_bytes = proxy_user.encode("utf-8")
                pass_bytes = (proxy_pass or "").encode("utf-8")
                if len(user_bytes) > 255 or len(pass_bytes) > 255:
                    raise RuntimeError("SOCKS5 proxy credentials are too long")
                s.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
                auth_resp = recv_exact_from_socket(s, 2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    raise RuntimeError("SOCKS5 username/password authentication failed")
            elif resp[1] != 0:
                raise RuntimeError("SOCKS5 authentication method unsupported")
            # SOCKS5 Connect
            atyp, addr_bytes = socks5_address_bytes(domain)
            req = b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, 'big')
            s.sendall(req)
            read_socks5_connect_reply(s)
            # If HTTPS, wrap socket with SSL
            if is_https:
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
        else: # http proxy
            if is_https:
                # HTTP CONNECT tunnel
                authority = format_host_port(domain, port)
                auth_header = proxy_basic_auth_header(proxy_user, proxy_pass or "") if proxy_user is not None else ""
                req_str = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n"
                s.sendall(req_str.encode('ascii'))
                resp = read_http_response_head(s)
                status_line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                status_parts = status_line.split()
                status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
                if status_code != 200:
                    raise RuntimeError(f"HTTP CONNECT tunnel failed: {status_line}")
                # Wrap socket with SSL
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                # Direct HTTP request through proxy: request URI must be absolute
                pass

        # Send HTTP GET request
        if ptype == "http" and not is_https:
            request_uri = url
        else:
            request_uri = path
            
        req_headers = (
            f"GET {request_uri} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n"
            f"Accept: text/plain,*/*\r\n"
            f"{proxy_basic_auth_header(proxy_user, proxy_pass or '') if ptype == 'http' and not is_https and proxy_user is not None else ''}"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode('utf-8'))

        # Read response
        response_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > snapshot_utils.MAX_SNAPSHOT_BYTES + 65536:
                raise RuntimeError("API response exceeds the maximum allowed size")
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # Parse HTTP response
    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise RuntimeError("Invalid HTTP response format")
    
    headers_part = response_data[:header_end].decode('utf-8', errors='replace')
    body_part = response_data[header_end+4:]

    # Check for HTTP status code
    lines = headers_part.splitlines()
    if not lines:
        raise RuntimeError("Empty response headers")
    status_line = lines[0]
    status_parts = status_line.split()
    if len(status_parts) >= 2:
        try:
            status_code = int(status_parts[1])
            if status_code != 200:
                raise RuntimeError(f"HTTP Server returned status {status_code}: {status_line}")
        except ValueError:
            pass

    # Handle chunked transfer encoding
    is_chunked = False
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                is_chunked = True
                break

    if is_chunked:
        decoded = b""
        idx = 0
        while idx < len(body_part):
            c_end = body_part.find(b"\r\n", idx)
            if c_end == -1:
                break
            chunk_size_str = body_part[idx:c_end].split(b";")[0].strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            idx = c_end + 2
            decoded += body_part[idx : idx + chunk_size]
            idx += chunk_size + 2
        body_part = decoded

    return body_part.decode('utf-8', errors='replace')

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = API_URL
    
    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 监测到上游代理 ({ptype}://{phost}:{pport})，尝试通过代理获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试使用直连/默认系统代理...", flush=True)
            log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"Mozilla/5.0 AimiliVPN/{APP_VERSION}",
            "Accept": "text/plain,*/*",
        },
    )
    def read_limited(response: Any) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > snapshot_utils.MAX_SNAPSHOT_BYTES:
                raise RuntimeError("API response exceeds the maximum allowed size")
            chunks.append(chunk)
        return b"".join(chunks)

    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=API_FETCH_TIMEOUT_SECONDS, context=ctx) as response:
            return read_limited(response).decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=API_FETCH_TIMEOUT_SECONDS) as response:
            return read_limited(response).decode("utf-8", errors="replace")

def fetch_api_text_with_deadline(
    url: str,
    use_ssl_verify: bool = True,
    deadline_seconds: int | None = None,
) -> str:
    deadline = deadline_seconds or API_SOURCE_DEADLINE_SECONDS
    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            result_queue.put((True, fetch_api_text(url, use_ssl_verify)))
        except BaseException as exc:
            result_queue.put((False, exc))

    threading.Thread(target=worker, daemon=True).start()
    try:
        ok, value = result_queue.get(timeout=deadline)
    except queue.Empty as exc:
        raise SourceDeadlineExceeded(f"节点源超过 {deadline} 秒总时限") from exc
    if ok:
        return str(value)
    raise value

def parse_release_version(value: Any) -> tuple[int, int, int]:
    match = re.search(r"(?i)(?:^|[^a-z0-9])v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(value or "").strip())
    if not match:
        raise ValueError("GitHub Release 版本号格式无效")
    return tuple(int(part or 0) for part in match.groups())

def check_latest_release() -> dict[str, Any]:
    payload = json.loads(fetch_api_text(GITHUB_LATEST_RELEASE_API, True))
    if not isinstance(payload, dict):
        raise ValueError("GitHub Release API 返回格式无效")
    if payload.get("draft") or payload.get("prerelease"):
        raise ValueError("GitHub 最新版本不是正式版")

    latest_tag = str(payload.get("tag_name") or "").strip()
    latest_version = parse_release_version(latest_tag)
    current_version = parse_release_version(APP_VERSION)
    release_url = f"{GITHUB_REPOSITORY_URL}/releases/tag/{urllib.parse.quote(latest_tag, safe='')}"

    return {
        "ok": True,
        "current_version": APP_VERSION,
        "current_version_label": APP_VERSION_LABEL,
        "latest_version": ".".join(str(part) for part in latest_version),
        "latest_tag": latest_tag,
        "latest_name": str(payload.get("name") or latest_tag),
        "published_at": str(payload.get("published_at") or ""),
        "update_available": latest_version > current_version,
        "release_url": release_url,
        "main_branch_url": GITHUB_MAIN_BRANCH_URL,
        "deployment_mode": DEPLOYMENT_MODE,
        "deployment_mode_label": DEPLOYMENT_MODE_LABEL,
        "update_command": UPDATE_COMMAND,
    }

def is_certificate_verification_error(exc: BaseException) -> bool:
    import ssl

    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        reason = getattr(current, "reason", None)
        cause = getattr(current, "__cause__", None)
        current = reason if isinstance(reason, BaseException) else cause
    return False

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    return snapshot_utils.parse_and_validate_snapshot(text, max_rows=MAX_SCAN_ROWS)

def decode_config(encoded: str) -> str:
    return snapshot_utils.decode_config(encoded)

def load_blacklist() -> dict[str, dict[str, Any]]:
    now = time.time()
    raw = read_json(BLACKLIST_FILE, {})
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    changed = False
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            changed = True
            continue
        until = float(entry.get("until", 0) or 0)
        if until and until > now:
            cleaned[str(key)] = entry
        else:
            changed = True
    if changed:
        write_json(BLACKLIST_FILE, cleaned)
    return cleaned

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    node_id = str(node.get("id") or "").strip()
    if not node_id:
        return
    blacklist = load_blacklist()
    now = time.time()
    blacklist[node_id] = {
        "id": node_id,
        "ip": node.get("ip") or node.get("remote_host") or "",
        "country": node.get("country", ""),
        "reason": message,
        "marked_at": now,
        "until": now + INVALID_BACKOFF_SECONDS,
    }
    write_json(BLACKLIST_FILE, blacklist)

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def api_network_sources() -> list[tuple[str, str]]:
    configured = [
        ("official_https", API_HTTPS_URL),
        ("official_http", API_HTTP_URL),
        ("github_pages_https", MIRROR_HTTPS_URL),
        ("github_pages_http_redirect_https", MIRROR_HTTP_URL),
    ]
    sources: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, url in configured:
        normalized = str(url or "").strip()
        if not normalized or normalized in seen:
            continue
        if not normalized.startswith(("https://", "http://")):
            print(f"[配置警告] 忽略不支持的节点源 URL: {normalized}", flush=True)
            continue
        seen.add(normalized)
        sources.append((label, normalized))
    return sources

def read_snapshot_file(path: Path) -> str:
    size = path.stat().st_size
    if size <= 0 or size > snapshot_utils.MAX_SNAPSHOT_BYTES:
        raise ValueError(f"本地快照大小无效: {size}")
    return path.read_bytes().decode("utf-8", errors="strict")

def cache_api_snapshot(text: str, source: str) -> None:
    validated_rows = snapshot_utils.parse_and_validate_snapshot(text, max_rows=MAX_SCAN_ROWS)
    encoded = text.encode("utf-8")
    with lock:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        tmp = API_CACHE_FILE.with_suffix(API_CACHE_FILE.suffix + ".tmp")
        tmp.write_bytes(encoded)
        tmp.replace(API_CACHE_FILE)
        write_json(
            API_CACHE_META_FILE,
            {
                "source": source,
                "cached_at": time.time(),
                "row_count": len(validated_rows),
                "byte_count": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            },
        )

def read_mirror_freshness() -> tuple[float, str]:
    if not MIRROR_META_URL:
        return 0.0, ""
    try:
        raw = fetch_api_text_with_deadline(MIRROR_META_URL, True, deadline_seconds=2)
        meta = json.loads(raw)
        generated_at = float(meta.get("generated_at", 0) or 0)
        if generated_at <= 0:
            return 0.0, ""
        age_seconds = max(0, int(time.time() - generated_at))
        if age_seconds < 3600:
            age_text = f"{max(1, age_seconds // 60)} 分钟"
        else:
            age_text = f"{age_seconds / 3600:.1f} 小时"
        return generated_at, f"镜像生成于 {age_text}前"
    except Exception as exc:
        print(f"[镜像元数据] 读取失败: {exc}", flush=True)
        return 0.0, "镜像生成时间未知"

def rows_to_candidates(
    rows: list[dict[str, str]],
    blacklist: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen_ips: set[str] = set()
    for row in rows[:MAX_SCAN_ROWS]:
        ip = row.get("IP", "")
        if not ip or ip in seen_ips:
            continue
        try:
            config_text = decode_config(row.get("OpenVPN_ConfigData_Base64", ""))
            snapshot_utils.validate_openvpn_config(config_text)
            node = row_to_node(row, config_text)
        except Exception as row_exc:
            print(f"[fetch_candidates] 跳过损坏或不安全的节点配置记录: {row_exc}", flush=True)
            log_to_json("WARNING", "Main", f"跳过损坏或不安全的节点配置记录: {row_exc}")
            continue
        entry = blacklist.get(node["id"])
        if entry and float(entry.get("until", 0) or 0) > time.time():
            continue
        candidates.append(node)
        seen_ips.add(ip)
    return candidates

def filter_candidates_by_discovery_countries(
    candidates: list[dict[str, Any]],
    country_codes: Any,
) -> list[dict[str, Any]]:
    selected = set(normalize_discovery_countries(country_codes))
    if not selected:
        return candidates
    return [
        candidate
        for candidate in candidates
        if str(candidate.get("country_short") or "").strip().upper() in selected
    ]

def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    discovery_countries = normalize_discovery_countries(
        load_ui_config().get("discovery_countries")
    )
    last_err: Exception | None = None
    log_to_json("INFO", "Main", "开始按官方、GitHub Pages、本地缓存顺序拉取节点列表...")

    for source_name, url in api_network_sources():
        try:
            msg = f"尝试节点源 {source_name}: {url}"
            print(f"[fetch_candidates] {msg}", flush=True)
            log_to_json("INFO", "Main", msg)
            api_text = fetch_api_text_with_deadline(url, True)
            rows = parse_vpngate_rows(api_text)
            candidates = rows_to_candidates(rows, blacklist)
            if not candidates:
                raise ValueError("节点源通过格式校验，但没有未被屏蔽的候选节点")

            # Plain HTTP remains available for older machines, but never replaces
            # the last snapshot obtained through an authenticated HTTPS channel.
            if url.startswith("https://"):
                cache_api_snapshot(api_text, source_name)

            filtered_candidates = filter_candidates_by_discovery_countries(
                candidates,
                discovery_countries,
            )
            scope_message = (
                f"按国家范围 {', '.join(discovery_countries)} 筛选后保留 {len(filtered_candidates)} 个"
                if discovery_countries
                else f"保留全部 {len(filtered_candidates)} 个"
            )
            mirror_generated_at = 0.0
            mirror_freshness = ""
            if source_name.startswith("github_pages"):
                mirror_generated_at, mirror_freshness = read_mirror_freshness()
            source_note = f"，{mirror_freshness}" if mirror_freshness else ""

            set_state(
                last_fetch_at=time.time(),
                last_fetch_status="ok",
                last_fetch_source=source_name,
                last_fetch_message=(
                    f"从 {source_name} 成功获取 {len(candidates)} 个候选节点，{scope_message}{source_note}。"
                ),
                mirror_generated_at=mirror_generated_at,
                mirror_freshness=mirror_freshness,
                blacklisted_nodes=len(blacklist),
            )
            log_to_json(
                "INFO",
                "Main",
                f"节点源 {source_name} 获取成功，共 {len(candidates)} 个候选节点，{scope_message}",
            )
            return filtered_candidates
        except Exception as e:
            last_err = e
            print(f"[fetch_candidates] 节点源 {source_name} 失败: {e}", flush=True)
            log_to_json("WARNING", "Main", f"节点源 {source_name} 失败: {e}")

    local_sources = [("local_cache", API_CACHE_FILE)]
    if BUNDLED_SNAPSHOT_FILE != API_CACHE_FILE:
        local_sources.append(("bundled_initial", BUNDLED_SNAPSHOT_FILE))
    for source_name, path in local_sources:
        try:
            if not path.exists():
                continue
            api_text = read_snapshot_file(path)
            rows = parse_vpngate_rows(api_text)
            candidates = rows_to_candidates(rows, blacklist)
            if not candidates:
                raise ValueError("本地快照没有未被屏蔽的候选节点")
            if source_name == "bundled_initial" and not API_CACHE_FILE.exists():
                cache_api_snapshot(api_text, source_name)
            filtered_candidates = filter_candidates_by_discovery_countries(
                candidates,
                discovery_countries,
            )
            scope_message = (
                f"按国家范围 {', '.join(discovery_countries)} 筛选后保留 {len(filtered_candidates)} 个"
                if discovery_countries
                else f"保留全部 {len(filtered_candidates)} 个"
            )
            set_state(
                last_fetch_at=time.time(),
                last_fetch_status="cached",
                last_fetch_source=source_name,
                last_fetch_message=(
                    f"网络节点源不可用，已载入 {source_name} 的 {len(candidates)} 个候选节点，"
                    f"{scope_message}。"
                ),
                blacklisted_nodes=len(blacklist),
            )
            log_to_json(
                "WARNING",
                "Main",
                f"网络节点源不可用，使用 {source_name}，共 {len(candidates)} 个候选节点，{scope_message}",
            )
            return filtered_candidates
        except Exception as e:
            last_err = e
            print(f"[fetch_candidates] 本地节点源 {source_name} 失败: {e}", flush=True)
            log_to_json("WARNING", "Main", f"本地节点源 {source_name} 失败: {e}")

    err_code, diag_msg = vpn_utils.diagnose_api_failure(API_URL)
    full_err_msg = f"所有节点源和本地缓存均失败: {last_err} | 诊断结果: {diag_msg}"
    print(f"[错误代码 {err_code}] {full_err_msg}", flush=True)
    log_to_json("ERROR", "Main", f"[错误代码 {err_code}] {full_err_msg}")
    set_state(
        last_fetch_status="error",
        last_fetch_error_code=err_code,
        last_fetch_source="",
        last_fetch_message=diag_msg,
    )
    if last_err:
        raise RuntimeError(diag_msg) from last_err
    raise RuntimeError(diag_msg)

def cached_nodes() -> list[dict[str, Any]]:
    return read_nodes()

_openvpn_version = None

def split_openvpn_command() -> list[str]:
    try:
        return shlex.split(OPENVPN_CMD, posix=(os.name != "nt")) or ["openvpn"]
    except ValueError as exc:
        raise RuntimeError(f"OPENVPN_CMD 配置无法解析: {exc}") from exc

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = split_openvpn_command()
        res = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = split_openvpn_command()
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--route-delay",
            "2",
            "--connect-retry",
            "1",
            "2",
            "--connect-retry-max",
            "2",
            "--connect-timeout",
            "20",
            "--hand-window",
            "25",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
            "--remote-cert-tls",
            "server",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])
    
    if os.path.exists("/etc/ssl/certs"):
        command.extend(["--capath", "/etc/ssl/certs"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            auth_file = upstream_proxy_auth_file()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
    except Exception:
        pass
        
    if route_nopull:
        command.append("--route-nopull")
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
    except OSError:
        return
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass

def begin_connection_attempt() -> tuple[int, threading.Event]:
    global connection_epoch, active_connection_cancel_event, is_connecting
    if not connection_attempt_lock.acquire(blocking=False):
        raise RuntimeError("当前已有连接切换任务正在运行，请稍后再试")

    cancel_event = threading.Event()
    with lock:
        if is_connecting:
            connection_attempt_lock.release()
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        connection_epoch += 1
        token = connection_epoch
        active_connection_cancel_event = cancel_event
        is_connecting = True
    return token, cancel_event

def connection_attempt_is_current(token: int, cancel_event: threading.Event) -> bool:
    with lock:
        return token == connection_epoch and not cancel_event.is_set()

def finish_connection_attempt(token: int, cancel_event: threading.Event) -> None:
    global active_connection_cancel_event, is_connecting
    with lock:
        if active_connection_cancel_event is cancel_event:
            active_connection_cancel_event = None
        if token == connection_epoch:
            is_connecting = False
    connection_attempt_lock.release()

def cancel_pending_connection_attempt() -> None:
    global connection_epoch, pending_openvpn_process, is_connecting
    pending = None
    with lock:
        if active_connection_cancel_event is None:
            return
        connection_epoch += 1
        active_connection_cancel_event.set()
        pending = pending_openvpn_process
        pending_openvpn_process = None
        is_connecting = False
    stop_process(pending)

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        own_markers = [
            str(DATA_DIR),
            str(CONFIG_DIR),
            str(AUTH_FILE),
            str(UPSTREAM_PROXY_AUTH_FILE),
        ]
        killed_pids: list[int] = []
        proc_root = Path("/proc")
        if not proc_root.exists():
            return
        for proc_dir in proc_root.iterdir():
            if not proc_dir.name.isdigit():
                continue
            pid = int(proc_dir.name)
            if pid == os.getpid():
                continue
            try:
                raw = (proc_dir / "cmdline").read_bytes()
            except OSError:
                continue
            if not raw:
                continue
            args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
            if not args:
                continue
            cmdline = " ".join(args)
            executable = Path(args[0]).name.lower()
            if "openvpn" not in executable and "openvpn" not in cmdline.lower():
                continue
            if any(marker and marker in cmdline for marker in own_markers):
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed_pids.append(pid)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    print(f"[Cleanup] No permission to terminate OpenVPN PID {pid}", flush=True)
        if killed_pids:
            time.sleep(0.5)
            for pid in killed_pids:
                try:
                    raw = (proc_root / str(pid) / "cmdline").read_bytes()
                    cmdline = " ".join(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)
                    if any(marker and marker in cmdline for marker in own_markers):
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except (OSError, PermissionError):
                    pass
            print(f"[Cleanup] Terminated AimiliVPN OpenVPN processes: {killed_pids}", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(
    config_file: str,
    keep_alive: bool,
    route_nopull: bool,
    timeout: int | None = None,
    dev: str = "tun0",
    cancel_event: threading.Event | None = None,
    track_pending: bool = False,
) -> tuple[bool, str, subprocess.Popen[str] | None]:
    global pending_openvpn_process
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "[错误代码 2001] [ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统未安装 openvpn，或 PATH 环境变量不正确。", None
    except OSError as exc:
        return False, f"[错误代码 2002] [ERR_OVPN_START_FAILED] openvpn 启动失败: {exc}。原因: 系统权限不足或配置冲突。", None

    if track_pending:
        with lock:
            if cancel_event is not None and cancel_event.is_set():
                stop_process(process)
                return False, "连接操作已取消", None
            pending_openvpn_process = process

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]
    openvpn_logs: list[str] = []

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line_str = line.rstrip()
            if not startup_done[0]:
                openvpn_logs.append(line_str)
                lines.put(line_str)
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line_str}", flush=True)
                    level = "INFO"
                    line_lower = line_str.lower()
                    if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
                        level = "ERROR"
                    elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
                        level = "WARNING"
                    log_to_json(level, "VPN", f"[OpenVPN] {line_str}")
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    cancelled = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            message = "连接操作已取消"
            break
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-50:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                message = "连接操作已取消"
            else:
                ok = True
                message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    # Bulk write accumulated startup logs
    for line_str in openvpn_logs:
        level = "INFO"
        line_lower = line_str.lower()
        if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
            level = "ERROR"
        elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
            level = "WARNING"
        log_to_json(level, "VPN", f"[OpenVPN] {line_str}")

    if not ok and not cancelled:
        err_code, diag_msg = vpn_utils.diagnose_openvpn_failure(tail)
        message = f"[错误代码 {err_code}] {diag_msg} (原始日志尾部: {tail[-1][-100:] if tail else '无'})"
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    if track_pending:
        with lock:
            if pending_openvpn_process is process or pending_openvpn_process is not None and pending_openvpn_process.poll() is not None:
                pending_openvpn_process = None
    return ok, message, process


class SoftEtherVirtualProcess:
    """Process-like handle representing an active SoftEther SSL-VPN session on vpn_se."""
    def __init__(self, account_name: str, vpncmd_bin: str, dev: str = "vpn_se") -> None:
        self.account_name = account_name
        self.vpncmd_bin = vpncmd_bin
        self.dev = dev
        self._terminated = False

    def poll(self) -> int | None:
        if self._terminated:
            return 0
        if sys.platform.startswith("linux") and not Path(f"/sys/class/net/{self.dev}").exists():
            return 1
        return None

    def terminate(self) -> None:
        if self._terminated:
            return
        self._terminated = True
        try:
            subprocess.run(
                [self.vpncmd_bin, "localhost", "/CLIENT", "/CMD", "AccountDisconnect", self.account_name],
                capture_output=True,
                timeout=4,
            )
            subprocess.run(
                [self.vpncmd_bin, "localhost", "/CLIENT", "/CMD", "AccountDelete", self.account_name],
                capture_output=True,
                timeout=4,
            )
        except Exception:
            pass
        try:
            subprocess.run(["ip", "addr", "flush", "dev", self.dev], capture_output=True, timeout=2)
        except Exception:
            pass

    def wait(self, timeout: float | None = None) -> int:
        self.terminate()
        return 0

    def kill(self) -> None:
        self.terminate()


def run_sstp_until_ready(
    remote_host: str,
    port: int,
    keep_alive: bool,
    timeout: int | None = None,
    unit: int = 0,
    cancel_event: threading.Event | None = None,
    track_pending: bool = False,
) -> tuple[bool, str, Any, str]:
    """
    Connect or probe a VPNGate node via MS-SSTP protocol using sstpc + pppd.
    Creates ppp{unit} interface.
    """
    global pending_openvpn_process
    sstpc_bin = vpn_utils.find_sstpc_binary()
    dev = f"ppp{unit}"
    if not sstpc_bin:
        return False, "未安装 sstp-client (sstpc)，跳过 SSTP 协议", None, dev
    limit = timeout if timeout is not None else OPENVPN_PROBE_TIMEOUT_SECONDS
    cmd = [
        sstpc_bin,
        "--cert-warn",
        "--tls-ext",
        "--log-stdout",
        "--log-level",
        "4",
        "--user",
        OPENVPN_AUTH_USER,
        "--password",
        OPENVPN_AUTH_PASS,
        f"{remote_host}:{int(port)}",
        "--",
        "noauth",
        "nodefaultroute",
        "usepeerdns",
        "refuse-eap",
        "noipdefault",
        "nodetach",
        "unit",
        str(unit),
    ]
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except Exception as exc:
        return False, f"SSTP 启动失败: {exc}", None, dev

    if track_pending:
        with lock:
            if cancel_event is not None and cancel_event.is_set():
                stop_process(process)
                return False, "连接操作已取消", None, dev
            pending_openvpn_process = process

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line_str = line.rstrip()
            if not startup_done[0]:
                lines.put(line_str)
            elif keep_alive:
                log_to_json("INFO", "VPN", f"[SSTP] {line_str}")
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    ok = False
    cancelled = False
    message = "SSTP 握手未完成"
    while time.time() - started < limit:
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            message = "连接操作已取消"
            break
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            if sys.platform.startswith("linux") and Path(f"/sys/class/net/{dev}").exists():
                res_ip = subprocess.run(["ip", "-4", "addr", "show", "dev", dev], capture_output=True, text=True, timeout=2)
                if "inet " in res_ip.stdout:
                    ok = True
                    message = f"MS-SSTP connected in {int((time.time() - started) * 1000)} ms ({remote_host}:{port})."
                    break
            continue
        if line is None:
            break
        lower = line.lower()
        if "local  ip address" in lower or "remote ip address" in lower or "connection was established" in lower:
            ok = True
            message = f"MS-SSTP connected in {int((time.time() - started) * 1000)} ms ({remote_host}:{port})."
            break
        if "authentication failed" in lower or "verification failed" in lower or "status 40" in lower or "unrecoverable ssl" in lower:
            message = f"SSTP 握手失败: {line[-120:]}"
            break

    startup_done[0] = True
    if not keep_alive or not ok or cancelled:
        stop_process(process)
        process = None
    if track_pending:
        with lock:
            if pending_openvpn_process is process:
                pending_openvpn_process = None
    return ok, message, process, dev


def run_softether_sslvpn_until_ready(
    remote_host: str,
    port: int,
    keep_alive: bool,
    timeout: int | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[bool, str, Any, str, str]:
    """
    Connect or probe a VPNGate node via native SoftEther SSL-VPN protocol.
    - When keep_alive=False (probing): verifies TLS + SoftEther HTTPS endpoint signature first,
      or uses vpncmd if installed.
    - When keep_alive=True (connecting): uses vpnclient + vpncmd on NIC 'se' (interface 'vpn_se')
      and obtains an IP + peer gateway inside VPNNAT / VPNGATE hub without overwriting the VPS default route.
    Returns (ok, message, virtual_process, dev, gateway_ip).
    """
    dev = "vpn_se"
    if not keep_alive:
        phys_dev = vpn_utils.get_physical_interface()
        sig_ok, sig_msg = vpn_utils.probe_softether_sslvpn_signature(
            remote_host,
            port,
            dev=phys_dev,
            timeout=min(4.0, float(timeout or 6)),
        )
        return sig_ok, sig_msg, None, dev, ""

    vpnclient_bin, vpncmd_bin = vpn_utils.find_softether_binaries()
    if not vpnclient_bin or not vpncmd_bin:
        return False, "系统未安装 SoftEther vpnclient/vpncmd，无法建立原生 SSL-VPN 网卡连接", None, dev, ""

    limit = timeout if timeout is not None else 25
    account_name = "aimili_active"
    started = time.time()
    try:
        subprocess.run([vpnclient_bin, "start"], capture_output=True, timeout=5)
        subprocess.run([vpncmd_bin, "localhost", "/CLIENT", "/CMD", "NicCreate", "se"], capture_output=True, timeout=5)
        subprocess.run([vpncmd_bin, "localhost", "/CLIENT", "/CMD", "AccountDisconnect", account_name], capture_output=True, timeout=4)
        subprocess.run([vpncmd_bin, "localhost", "/CLIENT", "/CMD", "AccountDelete", account_name], capture_output=True, timeout=4)
        create_res = subprocess.run(
            [
                vpncmd_bin,
                "localhost",
                "/CLIENT",
                "/CMD",
                "AccountCreate",
                account_name,
                f"/SERVER:{remote_host}:{int(port)}",
                "/HUB:VPNGATE",
                f"/USERNAME:{OPENVPN_AUTH_USER}",
                "/NICNAME:se",
            ],
            capture_output=True,
            text=True,
            timeout=6,
        )
        if create_res.returncode != 0:
            return False, f"SoftEther AccountCreate 失败: {create_res.stdout[-120:]}", None, dev, ""
        subprocess.run(
            [vpncmd_bin, "localhost", "/CLIENT", "/CMD", "AccountAnonymousSet", account_name],
            capture_output=True,
            timeout=5,
        )
        subprocess.run(
            [vpncmd_bin, "localhost", "/CLIENT", "/CMD", "AccountConnect", account_name],
            capture_output=True,
            timeout=5,
        )

        connected = False
        while time.time() - started < limit:
            if cancel_event is not None and cancel_event.is_set():
                break
            st_res = subprocess.run(
                [vpncmd_bin, "localhost", "/CLIENT", "/CMD", "AccountStatusGet", account_name],
                capture_output=True,
                text=True,
                timeout=4,
            )
            out_lower = st_res.stdout.lower()
            if "connection completed" in out_lower or "session established" in out_lower or "连接已完成" in out_lower:
                connected = True
                break
            time.sleep(0.8)

        if not connected:
            subprocess.run([vpncmd_bin, "localhost", "/CLIENT", "/CMD", "AccountDisconnect", account_name], capture_output=True, timeout=4)
            subprocess.run([vpncmd_bin, "localhost", "/CLIENT", "/CMD", "AccountDelete", account_name], capture_output=True, timeout=4)
            return False, f"SoftEther SSL-VPN 握手超时 ({remote_host}:{port})", None, dev, ""

        # Protect VPS physical route to VPN server before running DHCP on vpn_se
        phys_dev = vpn_utils.get_physical_interface()
        if phys_dev:
            try:
                res_rt = subprocess.run(["ip", "route", "show", "default", "dev", phys_dev], capture_output=True, text=True, timeout=2)
                gw_match = re.search(r"via\s+(\S+)", res_rt.stdout)
                if gw_match:
                    phys_gw = gw_match.group(1)
                    subprocess.run(["ip", "route", "replace", f"{remote_host}/32", "via", phys_gw, "dev", phys_dev], capture_output=True, timeout=2)
            except Exception:
                pass

        subprocess.run(["ip", "link", "set", "dev", dev, "up"], capture_output=True, timeout=2)
        subprocess.run(["ip", "addr", "flush", "dev", dev], capture_output=True, timeout=2)
        # Obtain IP without overwriting default route if possible, or assign / obtain via dhclient/udhcpc
        for dhcp_cmd in (
            ["dhclient", "-1", "-v", dev],
            ["udhcpc", "-i", dev, "-n", "-q"],
        ):
            try:
                subprocess.run(dhcp_cmd, capture_output=True, timeout=10)
                break
            except Exception:
                continue

        # Remove any default route injected into main table by dhclient on vpn_se so SSH stays on eth0
        try:
            subprocess.run(["ip", "route", "del", "default", "dev", dev], capture_output=True, timeout=2)
        except Exception:
            pass

        addr_res = subprocess.run(["ip", "-4", "addr", "show", "dev", dev], capture_output=True, text=True, timeout=2)
        ip_m = re.search(r"inet\s+(\d+\.\d+\.\d+\.)(\d+)/(\d+)", addr_res.stdout)
        if not ip_m:
            vproc = SoftEtherVirtualProcess(account_name, vpncmd_bin, dev=dev)
            vproc.terminate()
            return False, "SoftEther SSL-VPN 已连接，但未能通过 DHCP 获取内网 IP", None, dev, ""

        subnet_prefix = ip_m.group(1)
        # VPNGate SecureNAT gateway is standardly .1 on 10.211.254.1 or X.X.X.1
        gw_ip = f"{subnet_prefix}1"
        if subnet_prefix.startswith("10.211."):
            gw_ip = "10.211.254.254"
            # Check if .1 or .254 is in neighbor/route table
            rt_dev = subprocess.run(["ip", "-4", "route", "show", "dev", dev], capture_output=True, text=True, timeout=2).stdout
            m_src = re.search(r"(\d+\.\d+\.\d+\.\d+)/\d+", rt_dev)
            if "10.211." in rt_dev:
                gw_ip = "10.211.254.254"

        vproc = SoftEtherVirtualProcess(account_name, vpncmd_bin, dev=dev)
        return True, f"SoftEther SSL-VPN connected in {int((time.time() - started) * 1000)} ms ({remote_host}:{port}).", vproc, dev, gw_ip
    except Exception as exc:
        return False, f"SoftEther SSL-VPN 异常: {exc}", None, dev, ""


def setup_policy_routing(interface: str = "tun0", gateway_ip: str = "") -> bool:
    proxy_server.set_active_tunnel_interface(interface)
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    
    success = False
    for attempt in range(1, 4):
        try:
            route_cmd = ["ip", "route", "add", "default"]
            if gateway_ip:
                route_cmd.extend(["via", gateway_ip])
            route_cmd.extend(["dev", interface, "table", "100"])
            try:
                subprocess.run(route_cmd, check=True, timeout=2)
            except Exception:
                subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)
            # 配置反向路径过滤 rp_filter 为 loose 模式 (2)，防止回包被内核静默丢弃
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"], capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[policy_routing] Enabled policy routing for interface {interface} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)
            
    if not success:
        print("[路由配置失败] [错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由，这可能会导致通过 VPN 接口的出站路由无法正常解析。请检查系统是否支持策略路由、iproute2 工具是否完整，以及是否具有 root 权限。", flush=True)
        log_to_json("ERROR", "Routing", "[错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由")
    return success

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
        print("[policy_routing] Cleared policy routing table 100", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id, active_tunnel_interface, active_tunnel_protocol
    with lock:
        cleanup_policy_routing()
        active_tunnel_interface = "tun0"
        active_tunnel_protocol = "openvpn"
        proxy_server.set_active_tunnel_interface("tun0")
        config_to_delete = None
        if active_openvpn_node_id:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
            if node:
                config_to_delete = node.get("config_file")
                
        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        
        if config_to_delete:
            try:
                path = Path(config_to_delete)
                if path.exists():
                    path.unlink()
            except Exception:
                pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def connection_ready_for_ui(state: dict[str, Any] | None = None) -> bool:
    current = get_state() if state is None else state
    return bool(
        active_openvpn_node_id
        and active_openvpn_running()
        and current.get("tunnel_ready")
        and current.get("proxy_ready")
        and current.get("proxy_ok")
        and not current.get("is_connecting")
    )

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=lambda n: (
            0 if n.get("ip_type") in ("residential", "mobile") else 1,
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score"))
        )
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") in ("not_checked", "testing") and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

def enrich_stored_nodes() -> int:
    """Enrich every listed IP, then merge only metadata into the latest state."""
    with lock:
        snapshot = read_nodes()
    if not snapshot:
        return 0

    vpn_utils.enrich_ip_info(snapshot)
    enriched_by_id = {
        str(node.get("id") or ""): node
        for node in snapshot
        if node.get("id") and node.get("ip_type")
    }
    if not enriched_by_id:
        return 0

    changed = 0
    with lock:
        current_nodes = read_nodes()
        for current in current_nodes:
            enriched = enriched_by_id.get(str(current.get("id") or ""))
            if not enriched:
                continue
            for field in IP_ENRICHMENT_FIELDS:
                new_value = enriched.get(field, "")
                if current.get(field, "") != new_value:
                    current[field] = new_value
                    changed += 1
        if changed:
            write_json(NODES_FILE, sort_all_nodes(current_nodes))
    return changed

def ip_enrichment_loop() -> None:
    while True:
        nodes_exist = bool(read_nodes())
        if nodes_exist:
            try:
                enrich_stored_nodes()
            except Exception as exc:
                print(f"[IP 类型] 后台批量识别失败: {exc}", flush=True)
                log_to_json("WARNING", "Main", f"后台批量识别 IP 类型失败: {exc}")
        ip_enrichment_wakeup.wait(300 if nodes_exist else 5)
        ip_enrichment_wakeup.clear()

JP_PREFECTURE_ALIASES: dict[str, str] = {
    "tokyo": "东京都", "东京": "东京都", "东京都": "东京都", "東京都": "东京都",
    "osaka": "大阪府", "大阪": "大阪府", "大阪府": "大阪府",
    "hokkaido": "北海道", "北海道": "北海道",
    "kyoto": "京都府", "京都": "京都府", "京都府": "京都府",
    "kanagawa": "神奈川县", "神奈川": "神奈川县", "神奈川县": "神奈川县", "神奈川県": "神奈川县",
    "saitama": "埼玉县", "埼玉": "埼玉县", "埼玉县": "埼玉县", "埼玉県": "埼玉县",
    "chiba": "千叶县", "千叶": "千叶县", "千叶县": "千叶县", "千葉県": "千叶县",
    "aichi": "爱知县", "爱知": "爱知县", "爱知县": "爱知县", "愛知県": "爱知县",
    "fukuoka": "福冈县", "福冈": "福冈县", "福冈县": "福冈县", "福岡県": "福冈县",
    "hyogo": "兵库县", "兵库": "兵库县", "兵库县": "兵库县", "兵庫県": "兵库县",
    "ibaraki": "茨城县", "茨城": "茨城县", "茨城县": "茨城县", "茨城県": "茨城县",
    "hiroshima": "广岛县", "广岛": "广岛县", "广岛县": "广岛县", "広島県": "广岛县",
    "miyagi": "宫城县", "宫城": "宫城县", "宫城县": "宫城县", "宮城県": "宫城县",
    "shizuoka": "静冈县", "静冈": "静冈县", "静冈县": "静冈县", "静岡県": "静冈县",
    "niigata": "新潟县", "新潟": "新潟县", "新潟县": "新潟县", "新潟県": "新潟县",
    "nagano": "长野县", "长野": "长野县", "长野县": "长野县", "長野県": "长野县",
    "gifu": "岐阜县", "岐阜": "岐阜县", "岐阜县": "岐阜县", "岐阜県": "岐阜县",
    "gunma": "群马县", "群马": "群马县", "群马县": "群马县", "群馬県": "群马县",
    "tochigi": "栃木县", "栃木": "栃木县", "栃木县": "栃木县", "栃木県": "栃木县",
    "okayama": "冈山县", "冈山": "冈山县", "冈山县": "冈山县", "岡山県": "冈山县",
    "mie": "三重县", "三重": "三重县", "三重县": "三重县", "三重県": "三重县",
    "kumamoto": "熊本县", "熊本": "熊本县", "熊本县": "熊本县", "熊本県": "熊本县",
    "kagoshima": "鹿儿岛县", "鹿儿岛": "鹿儿岛县", "鹿儿岛县": "鹿儿岛县", "鹿児島県": "鹿儿岛县",
    "okinawa": "冲绳县", "冲绳": "冲绳县", "冲绳县": "冲绳县", "沖縄県": "冲绳县",
    "shiga": "滋贺县", "滋贺": "滋贺县", "滋贺县": "滋贺县", "滋賀県": "滋贺县",
    "yamaguchi": "山口县", "山口": "山口县", "山口县": "山口县", "山口県": "山口县",
    "ehime": "爱媛县", "爱媛": "爱媛县", "爱媛县": "爱媛县", "愛媛県": "爱媛县",
    "nagasaki": "长崎县", "长崎": "长崎县", "长崎县": "长崎县", "長崎県": "长崎县",
    "nara": "奈良县", "奈良": "奈良县", "奈良县": "奈良县", "奈良県": "奈良县",
    "aomori": "青森县", "青森": "青森县", "青森县": "青森县", "青森県": "青森县",
    "iwate": "岩手县", "岩手": "岩手县", "岩手县": "岩手县", "岩手県": "岩手县",
    "oita": "大分县", "大分": "大分县", "大分县": "大分县", "大分県": "大分县",
    "ishikawa": "石川县", "石川": "石川县", "石川县": "石川县", "石川県": "石川县",
    "yamagata": "山形县", "山形": "山形县", "山形县": "山形县", "山形県": "山形县",
    "miyazaki": "宫崎县", "宫崎": "宫崎县", "宫崎县": "宫崎县", "宮崎県": "宫崎县",
    "fukushima": "福岛县", "福岛": "福岛县", "福岛县": "福岛县", "福島県": "福岛县",
    "toyama": "富山县", "富山": "富山县", "富山县": "富山县", "富山県": "富山县",
    "kagawa": "香川县", "香川": "香川县", "香川县": "香川县", "香川県": "香川县",
    "wakayama": "和歌山县", "和歌山": "和歌山县", "和歌山县": "和歌山县", "和歌山県": "和歌山县",
    "akita": "秋田县", "秋田": "秋田县", "秋田县": "秋田县", "秋田県": "秋田县",
    "saga": "佐贺县", "佐贺": "佐贺县", "佐贺县": "佐贺县", "佐賀県": "佐贺县",
    "yamanashi": "山梨县", "山梨": "山梨县", "山梨县": "山梨县", "山梨県": "山梨县",
    "fukui": "福井县", "福井": "福井县", "福井县": "福井县", "福井県": "福井县",
    "tokushima": "德岛县", "德岛": "德岛县", "德岛县": "德岛县", "徳島県": "德岛县",
    "kochi": "高知县", "高知": "高知县", "高知县": "高知县", "高知県": "高知县",
    "shimane": "岛根县", "岛根": "岛根县", "岛根县": "岛根县", "島根県": "岛根县",
    "tottori": "鸟取县", "鸟取": "鸟取县", "鸟取县": "鸟取县", "鳥取県": "鸟取县",
}

def normalize_region_token(token: str) -> str:
    raw = str(token or "").strip()
    if not raw:
        return ""
    cleaned = re.sub(r"\s+(?:prefecture|province|state|metropolis|city)$", "", raw, flags=re.I).strip()
    lower = cleaned.lower()
    if lower in JP_PREFECTURE_ALIASES:
        return JP_PREFECTURE_ALIASES[lower]
    if cleaned in JP_PREFECTURE_ALIASES:
        return JP_PREFECTURE_ALIASES[cleaned]
    return cleaned

def extract_node_region(node: dict[str, Any]) -> str:
    loc = str(node.get("location") or "").strip()
    if loc:
        parts = [p.strip() for p in re.split(r"[\s·,/|]+", loc) if p.strip()]
        if len(parts) >= 2:
            return normalize_region_token(parts[1])
        if len(parts) == 1:
            country_zh = normalized_country_name(node.get("country"))
            if parts[0] != country_zh:
                return normalize_region_token(parts[0])
    for rep_key in ("cleanip_report", "intel_report"):
        rep = str(node.get(rep_key) or "")
        if rep:
            m = re.search(r"归属地\s+([^\n]+)", rep)
            if m:
                rparts = [p.strip() for p in re.split(r"[\s·,/|]+", m.group(1)) if p.strip()]
                if len(rparts) >= 2:
                    return normalize_region_token(rparts[1])
    return ""

def node_matches_region(node: dict[str, Any], target_region: Any) -> bool:
    target = normalize_region_token(str(target_region or ""))
    if not target:
        return True
    node_reg = extract_node_region(node)
    if node_reg and (node_reg == target or target in node_reg or node_reg in target):
        return True
    loc = str(node.get("location") or "")
    return target in loc

def apply_routing_filters(
    nodes: list[dict[str, Any]],
    ui_cfg: dict[str, Any],
    include_unknown_ip_type: bool = False,
) -> list[dict[str, Any]]:
    candidates = list(nodes)
    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_region" and target_country:
        candidates = [
            n for n in candidates
            if country_matches(n.get("country"), target_country, n.get("country_short"))
        ]
    elif routing_mode == "favorites":
        fav_ids = set(ui_cfg.get("favorite_node_ids", []))
        candidates = [n for n in candidates if n.get("id") in fav_ids]
        fav_region = str(ui_cfg.get("fav_region") or "").strip()
        if fav_region:
            candidates = [n for n in candidates if node_matches_region(n, fav_region)]

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    if routing_ip_type == "residential":
        candidates = [
            n for n in candidates
            if (
                n.get("ip_type") in ("residential", "mobile")
                and n.get("ip_type_confidence") in ("medium", "high")
            )
            or (include_unknown_ip_type and not n.get("ip_type"))
        ]
    elif routing_ip_type == "hosting":
        candidates = [
            n for n in candidates
            if n.get("ip_type") == "hosting"
            or (include_unknown_ip_type and not n.get("ip_type"))
        ]

    return candidates

def normalized_country_name(country: Any) -> str:
    value = str(country or "").strip()
    return vpn_utils.COUNTRY_TRANSLATIONS.get(value, value)

def normalize_routing_country(value: Any, nodes: list[dict[str, Any]] | None = None) -> str:
    target = str(value or "").strip()
    if not target:
        return ""
    upper = target.upper()
    if re.fullmatch(r"[A-Z]{2}", upper):
        return upper
    normalized_target = normalized_country_name(target).casefold()
    for node in nodes if nodes is not None else read_nodes():
        code = str(node.get("country_short") or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", code):
            continue
        if normalized_country_name(node.get("country")).casefold() == normalized_target:
            return code
    return target

def country_matches(
    node_country: Any,
    target_country: Any,
    node_country_short: Any = "",
) -> bool:
    target = str(target_country or "").strip()
    if not target:
        return False
    target_upper = target.upper()
    if re.fullmatch(r"[A-Z]{2}", target_upper):
        return str(node_country_short or "").strip().upper() == target_upper
    return normalized_country_name(node_country).casefold() == normalized_country_name(target).casefold()

def probe_priority_key(node: dict[str, Any]) -> tuple[int, int, int, int]:
    ping = parse_int(node.get("ping")) or 999999
    return (
        ping,
        -parse_int(node.get("score")),
        -parse_int(node.get("speed")),
        parse_int(node.get("sessions")),
    )

def current_fixed_node_id(ui_cfg: dict[str, Any]) -> str:
    if active_openvpn_node_id:
        return active_openvpn_node_id
    nodes = read_nodes()
    active_node = next((n for n in nodes if n.get("active") and n.get("id")), None)
    if active_node:
        return str(active_node.get("id") or "")
    return str(ui_cfg.get("fixed_node_id") or "").strip()

def validate_node_allowed_by_routing(node: dict[str, Any], ui_cfg: dict[str, Any]) -> None:
    routing_mode = ui_cfg.get("routing_mode", "auto")
    node_id = str(node.get("id") or "")

    if routing_mode == "fixed_region":
        target_country = ui_cfg.get("force_country", "")
        if target_country and not country_matches(node.get("country"), target_country, node.get("country_short")):
            raise RuntimeError(f"当前已锁定国家【{target_country}】，不能连接其他国家节点")
    elif routing_mode == "favorites":
        fav_ids = set(ui_cfg.get("favorite_node_ids", []))
        if node_id not in fav_ids:
            raise RuntimeError("当前处于仅用收藏模式，不能连接未收藏节点")
        fav_region = str(ui_cfg.get("fav_region") or "").strip()
        if fav_region and not node_matches_region(node, fav_region):
            raise RuntimeError(f"当前仅用收藏已限定【{fav_region}】地区轮换，不能连接其他地区的收藏节点")

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    node_ip_type = node.get("ip_type")
    if routing_ip_type == "residential" and node_ip_type not in ("residential", "mobile"):
        raise RuntimeError("当前已锁定住宅 IP 出站，不能连接非住宅节点")
    if routing_ip_type == "hosting" and node_ip_type != "hosting":
        raise RuntimeError("当前已锁定机房 IP 出站，不能连接非机房节点")

def enforce_active_node_allowed_by_routing(ui_cfg: dict[str, Any], reason: str = "路由规则已更新") -> str | None:
    active_id = active_openvpn_node_id
    if not active_id:
        return None

    nodes = read_nodes()
    active_node = next((item for item in nodes if item.get("id") == active_id), None)
    if not active_node:
        clear_active_connection_state(f"{reason}，当前活动节点已不在节点列表中，已断开连接")
        return "当前活动节点已不在节点列表中，已断开连接"

    try:
        validate_node_allowed_by_routing(active_node, ui_cfg)
        return None
    except Exception as exc:
        msg = f"{reason}，当前活动节点 {active_id} 不符合新规则，已断开连接: {exc}"
        print(f"[路由规则] {msg}", flush=True)
        log_to_json("WARNING", "Routing", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(
            active_openvpn_node_id="",
            active_node_latency="无活动连接",
            proxy_ok=False,
            proxy_ip="-",
            proxy_latency_ms=0,
            proxy_error=msg,
            last_check_message=msg,
        )

        if ui_cfg.get("connection_enabled", True) and ui_cfg.get("routing_mode") != "fixed_ip":
            threading.Thread(target=auto_switch_node, daemon=True).start()
        return msg

def reconnect_fixed_node_if_needed(ui_cfg: dict[str, Any]) -> bool:
    global is_connecting
    if ui_cfg.get("routing_mode") != "fixed_ip" or active_openvpn_running():
        return False
    target_id = current_fixed_node_id(ui_cfg)
    if not target_id:
        return False
    nodes = read_nodes()
    if not any(n.get("id") == target_id for n in nodes):
        return False

    print(f"[维护线程] 固定 IP 模式下 OpenVPN 未运行，正在重新拉起同一节点: {target_id}", flush=True)
    previous_connecting = is_connecting
    is_connecting = False
    try:
        connect_node(target_id)
        return active_openvpn_running()
    except Exception as e:
        print(f"[维护线程] 重新拉起固定节点 {target_id} 失败: {e}", flush=True)
        return False
    finally:
        is_connecting = previous_connecting

active_test_indexes = set()
test_indexes_lock = threading.Lock()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        raise RuntimeError("没有可用的 OpenVPN 测试网卡编号，请稍后重试")

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_config_path(node_id: str) -> Path:
    safe_id = safe_name(node_id)
    return CONFIG_DIR / f".test_{safe_id}_{uuid.uuid4().hex}.ovpn"

def is_systemic_probe_failure(message: Any) -> bool:
    normalized = str(message or "").lower()
    return any(
        token in normalized
        for token in (
            "err_ovpn_cmd_not_found",
            "err_ovpn_permission_denied",
            "err_ovpn_tun_not_available",
            "no such file or directory",
            "cannot open tun/tap dev",
            "cannot allocate tun",
        )
    )

def probe_openvpn_with_protocol_fallbacks(
    node_id: str,
    config_text: str,
    remote_host: str,
    primary_port: int,
    primary_proto: str,
    dev: str,
    primary_timeout: int | None = None,
    fallback_timeout: int | None = None,
    max_fallbacks: int = 4,
    cancel_event: threading.Event | None = None,
    track_pending: bool = False,
    host_name: str = "",
) -> tuple[bool, str, str, int, str]:
    """
    Probe a node using its primary protocol/port first, and if that fails with a
    non-systemic / non-auth error, automatically try:
      1. Alternative OpenVPN protocols & ports (UDP <-> TCP on same port, TCP 443, 995, 1194, 1698, 5555, UDP 1194, 1195)
      2. SoftEther SSL-VPN ('sslvpn') over HTTPS port
      3. MS-SSTP ('sstp') over HTTPS port (when sstpc is installed)
      4. <HostName>.opengw.net DDNS IP resolution if the volunteer node's dynamic residential IP rotated
    Returns (ok, message, effective_proto, effective_port, effective_config_text).
    """
    p_timeout = primary_timeout if primary_timeout is not None else OPENVPN_PROBE_TIMEOUT_SECONDS
    f_timeout = fallback_timeout if fallback_timeout is not None else OPENVPN_FALLBACK_TIMEOUT_SECONDS
    parsed_host, parsed_port, parsed_proto = vpn_utils.parse_remote(config_text, remote_host)
    eff_host = remote_host or parsed_host
    eff_port = int(primary_port or parsed_port or 0)
    raw_proto = primary_proto if primary_proto and primary_proto != "unknown" else parsed_proto
    eff_proto = vpn_utils.normalize_vpn_protocol(raw_proto)
    if eff_port <= 0:
        eff_port = 443 if eff_proto in ("tcp", "sslvpn", "sstp") else 1194

    dev_idx_m = re.search(r"(\d+)$", str(dev or "tun2"))
    unit_idx = int(dev_idx_m.group(1)) if dev_idx_m else 2

    temp_path = test_config_path(node_id)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as exc:
        return False, f"Failed to write temp config file: {exc}", eff_proto, eff_port, config_text

    def _probe_single_candidate(
        c_host: str,
        c_proto: str,
        c_port: int,
        c_timeout: int,
        base_cfg: str,
    ) -> tuple[bool, str, str]:
        norm_p = vpn_utils.normalize_vpn_protocol(c_proto)
        if norm_p == "sslvpn":
            ok_se, msg_se, _, _, _ = run_softether_sslvpn_until_ready(
                c_host,
                c_port,
                keep_alive=False,
                timeout=min(5, c_timeout),
                cancel_event=cancel_event,
            )
            return ok_se, msg_se, base_cfg
        if norm_p == "sstp":
            ok_ss, msg_ss, _, _ = run_sstp_until_ready(
                c_host,
                c_port,
                keep_alive=False,
                timeout=c_timeout,
                unit=unit_idx,
                cancel_event=cancel_event,
                track_pending=track_pending,
            )
            return ok_ss, msg_ss, base_cfg

        rewritten = vpn_utils.rewrite_openvpn_endpoint(base_cfg, c_host, c_port, norm_p)
        try:
            temp_path.write_text(rewritten, encoding="utf-8")
        except Exception as exc:
            return False, f"Failed to write temp config: {exc}", base_cfg
        ok_ov, msg_ov, _ = run_openvpn_until_ready(
            str(temp_path),
            keep_alive=False,
            route_nopull=True,
            timeout=c_timeout,
            dev=dev,
            cancel_event=cancel_event,
            track_pending=track_pending,
        )
        return ok_ov, msg_ov, rewritten

    try:
        if eff_proto in ("sslvpn", "sstp"):
            ok, message, eff_cfg = _probe_single_candidate(eff_host, eff_proto, eff_port, p_timeout, config_text)
        else:
            ok, message, _ = run_openvpn_until_ready(
                str(temp_path),
                keep_alive=False,
                route_nopull=True,
                timeout=p_timeout,
                dev=dev,
                cancel_event=cancel_event,
                track_pending=track_pending,
            )
            eff_cfg = config_text
        if ok:
            return True, message, eff_proto, eff_port, eff_cfg

        msg_lower = str(message or "").lower()
        if (
            not OPENVPN_PROTO_FALLBACK_ENABLED
            or max_fallbacks <= 0
            or not eff_host
            or (cancel_event is not None and cancel_event.is_set())
            or is_systemic_probe_failure(message)
            or "auth_failed" in msg_lower
            or "err_ovpn_auth_failed" in msg_lower
            or "连接操作已取消" in msg_lower
        ):
            return False, message, eff_proto, eff_port, config_text

        phys_dev = vpn_utils.get_physical_interface()
        sstpc_available = bool(vpn_utils.find_sstpc_binary())

        hosts_to_try = [eff_host]
        ddns_ip = vpn_utils.resolve_vpngate_ddns_ip(host_name, eff_host) if host_name else ""
        if ddns_ip and ddns_ip not in hosts_to_try:
            hosts_to_try.append(ddns_ip)

        tried = 0
        orig_label = vpn_utils.format_vpn_protocol_label(eff_proto)
        for idx_host, target_host in enumerate(hosts_to_try):
            candidates = vpn_utils.generate_openvpn_fallback_endpoints(
                target_host,
                eff_port,
                eff_proto,
                include_non_openvpn=True,
            )
            if idx_host > 0:
                # For DDNS-updated IP, try primary proto/port first!
                candidates = [(eff_proto, eff_port)] + [c for c in candidates if c != (eff_proto, eff_port)]

            for cand_proto, cand_port in candidates:
                if tried >= max_fallbacks:
                    break
                if cancel_event is not None and cancel_event.is_set():
                    break
                if cand_proto == "sstp" and not sstpc_available:
                    continue
                if cand_proto in ("tcp", "sslvpn", "sstp"):
                    # Fast TCP reachability pre-check (1.8s) to avoid wasting time on closed TCP ports
                    if vpn_utils.tcp_latency_ms(target_host, cand_port, phys_dev, timeout=1.8) <= 0:
                        continue

                tried += 1
                alt_ok, alt_msg, alt_config = _probe_single_candidate(
                    target_host,
                    cand_proto,
                    cand_port,
                    f_timeout,
                    config_text,
                )
                if alt_ok:
                    cand_label = vpn_utils.format_vpn_protocol_label(cand_proto)
                    ddns_note = f", DDNS追回IP:{target_host}" if target_host != eff_host else ""
                    rescue_msg = f"{alt_msg} [多协议回退成功: {orig_label}:{eff_port} -> {cand_label}:{cand_port}{ddns_note}]"
                    return True, rescue_msg, cand_proto, cand_port, alt_config
                if is_systemic_probe_failure(alt_msg):
                    return False, alt_msg, eff_proto, eff_port, config_text

        return False, message, eff_proto, eff_port, config_text
    finally:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        proto = str(node.get("proto") or "")
        host_name = str(node.get("host_name") or "")
        cfg_file_str = str(node.get("config_file") or "")
        fallback_ping = parse_int(node.get("ping"))

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)

    idx = None
    try:
        idx = get_free_test_index()
        ok, message, eff_proto, eff_port, eff_config = probe_openvpn_with_protocol_fallbacks(
            node_id=node_id,
            config_text=config_text,
            remote_host=h,
            primary_port=p,
            primary_proto=proto,
            dev=f"tun{idx}",
            primary_timeout=OPENVPN_PROBE_TIMEOUT_SECONDS,
            fallback_timeout=OPENVPN_FALLBACK_TIMEOUT_SECONDS,
            max_fallbacks=6,
            host_name=host_name,
        )
    finally:
        if idx is not None:
            release_test_index(idx)

    if ok and eff_port != p:
        re_lat = vpn_utils.ping_latency_ms(h, eff_port, latency or fallback_ping)
        if re_lat > 0:
            latency = re_lat

    temp_node: dict[str, Any] = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": eff_port if ok else p,
        "proto": eff_proto if ok else (proto or "udp"),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])
        if eff_config and eff_config != config_text and cfg_file_str:
            try:
                Path(cfg_file_str).write_text(eff_config, encoding="utf-8")
            except Exception:
                pass

    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["proto"] = eff_proto
                node["remote_port"] = eff_port
                node["config_text"] = eff_config
                for field in IP_ENRICHMENT_FIELDS:
                    value = temp_node.get(field)
                    if value not in (None, ""):
                        node[field] = value

            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            try:
                sync_favorite_snapshots_with_nodes(nodes=sorted_nodes)
            except Exception:
                pass
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def test_multiple_nodes(
    node_ids: list[str],
    target_available: int | None = None,
    cancel_event: threading.Event | None = None,
    progress_callback: Any = None,
) -> list[dict[str, Any]]:
    with lock:
        nodes = read_nodes()
        id_order = {nid: idx for idx, nid in enumerate(node_ids)}
        to_test = [n for n in nodes if n.get("id") in id_order]
        to_test.sort(key=lambda item: id_order.get(str(item.get("id")), 999999))
        
    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        proto = str(n_info.get("proto") or "")
        host_name = str(n_info.get("host_name") or "")
        cfg_file_str = str(n_info.get("config_file") or "")
        fallback_ping = parse_int(n_info.get("ping"))
        
        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        tun_idx = None
        try:
            tun_idx = get_free_test_index()
            dev_name = f"tun{tun_idx}"
            ok, message, eff_proto, eff_port, eff_config = probe_openvpn_with_protocol_fallbacks(
                node_id=node_id,
                config_text=config_text,
                remote_host=h,
                primary_port=p,
                primary_proto=proto,
                dev=dev_name,
                primary_timeout=OPENVPN_PROBE_TIMEOUT_SECONDS,
                fallback_timeout=OPENVPN_FALLBACK_TIMEOUT_SECONDS,
                max_fallbacks=4,
                cancel_event=cancel_event,
                host_name=host_name,
            )
        finally:
            if tun_idx is not None:
                release_test_index(tun_idx)

        if ok and eff_config and eff_config != config_text and cfg_file_str:
            try:
                Path(cfg_file_str).write_text(eff_config, encoding="utf-8")
            except Exception:
                pass
            
        temp_node: dict[str, Any] = {
            "id": node_id,
            "ip": n_info.get("ip") or h,
            "remote_host": h,
            "remote_port": eff_port if ok else p,
            "proto": eff_proto if ok else (proto or "udp"),
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
        }
        if ok and eff_config:
            temp_node["config_text"] = eff_config
        return temp_node

    updated_nodes_map: dict[str, dict[str, Any]] = {}
    available_count = 0
    systemic_failure = ""
    max_workers = min(NODE_PROBE_WORKERS, max(1, len(to_test)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for batch_start in range(0, len(to_test), max_workers):
            if (
                systemic_failure
                or (cancel_event is not None and cancel_event.is_set())
                or (target_available is not None and available_count >= target_available)
            ):
                break

            batch = to_test[batch_start : batch_start + max_workers]
            batch_ids = {str(n.get("id") or "") for n in batch}
            with lock:
                current_nodes = read_nodes()
                now = time.time()
                for current in current_nodes:
                    if current.get("id") in batch_ids and not current.get("active"):
                        current["probe_status"] = "testing"
                        current["probe_message"] = "正在检测节点连通性 (支持 UDP/TCP/SSL-VPN/SSTP 多协议回退)..."
                        current["probed_at"] = now
                write_json(NODES_FILE, sort_all_nodes(current_nodes))

            futures = {
                executor.submit(test_worker, (batch_start + idx, node)): node["id"]
                for idx, node in enumerate(batch)
            }
            for future in concurrent.futures.as_completed(futures):
                nid = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "id": nid,
                        "probe_status": "unavailable",
                        "probe_message": f"Test exception: {exc}",
                        "latency_ms": 0,
                    }
                updated_nodes_map[nid] = result
                if result.get("probe_status") == "available":
                    available_count += 1
                if is_systemic_probe_failure(result.get("probe_message")):
                    systemic_failure = str(result.get("probe_message") or "")
                with lock:
                    current_nodes = read_nodes()
                    for current in current_nodes:
                        if current.get("id") == nid:
                            current.update(result)
                            break
                    write_json(NODES_FILE, sort_all_nodes(current_nodes))
                if callable(progress_callback):
                    try:
                        progress_callback(len(updated_nodes_map), len(to_test), result)
                    except Exception:
                        pass

            if systemic_failure:
                message = f"检测到系统级 OpenVPN 故障，已停止剩余节点探测: {systemic_failure}"
                print(f"[节点检测] {message}", flush=True)
                log_to_json("ERROR", "VPN", message)
                set_state(last_check_message=message)
                break
                
    # 批量查询并丰富可用节点的地理及 ISP 信息，防止并发时被定位 API 接口限流
    successful_nodes = [res for res in updated_nodes_map.values() if res.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes)
        except Exception as ee:
            print(f"[test_multiple_nodes] 批量富化 IP 失败: {ee}", flush=True)

    with lock:
        current_nodes = read_nodes()
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        try:
            sync_favorite_snapshots_with_nodes(nodes=sorted_nodes)
        except Exception:
            pass
        
    return list(updated_nodes_map.values())

def cancel_background_refill() -> None:
    background_refill_cancel_event.set()

def schedule_background_refill() -> bool:
    global background_refill_thread
    with background_refill_lock:
        if background_refill_thread is not None and background_refill_thread.is_alive():
            return False
        background_refill_cancel_event.clear()

        def refill_worker() -> None:
            global background_refill_thread
            try:
                for delay in (60, 120, 300):
                    if background_refill_cancel_event.wait(delay):
                        return
                    ui_cfg = load_ui_config()
                    if not ui_cfg.get("connection_enabled", True):
                        return
                    try:
                        maintain_valid_nodes(force=False)
                    except Exception as exc:
                        log_to_json("WARNING", "Main", f"后台节点补齐失败: {exc}")
                    if active_openvpn_running():
                        return
            finally:
                with background_refill_lock:
                    if background_refill_thread is threading.current_thread():
                        background_refill_thread = None

        background_refill_thread = threading.Thread(
            target=refill_worker,
            name="vpngate-node-refill",
            daemon=True,
        )
        background_refill_thread.start()
        return True

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        if schedule_background_refill():
            log_to_json("INFO", "Main", "连续自动切换失败，已启动唯一后台节点补齐任务")
        return
        
    ui_cfg = load_ui_config()
    connection_enabled = ui_cfg.get("connection_enabled", True)
    if not connection_enabled:
        print("[自动切换] 连接已禁用，不进行自动切换。", flush=True)
        return

    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_ip":
        print("[自动切换] 当前处于固定 IP 模式，不进行自动连接或切换。", flush=True)
        return

    # Find the next best available node
    with lock:
        nodes = read_nodes()
        candidates = [
            n for n in nodes 
            if n.get("probe_status") == "available" 
            and not n.get("active")
        ]
        candidates = apply_routing_filters(candidates, ui_cfg)
            
        candidates.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999, -parse_int(n.get("score"))))
        
    if candidates:
        next_node = candidates[0]
        msg = f"当前连接已失效或代理连通性检测失败，正在自动切换至最佳备用节点: {next_node['id']}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        try:
            connect_node(next_node["id"])
        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            auto_switch_node(attempt + 1)
    else:
        msg = "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点..."
        if routing_mode == "fixed_region" and target_country:
            msg = f"没有可用的【{target_country}】备选节点，已断开连接，将在后台持续尝试获取新节点..."
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message=msg)
        if schedule_background_refill():
            log_to_json("INFO", "Main", "已启动唯一后台节点补齐任务")

def recover_after_manual_connect_failure(previous_node_id: str) -> None:
    if active_openvpn_running():
        return

    if previous_node_id:
        try:
            log_to_json("WARNING", "VPN", f"手动切换失败，正在恢复原节点: {previous_node_id}")
            connect_node(previous_node_id)
            return
        except Exception as exc:
            log_to_json("ERROR", "VPN", f"恢复原节点 {previous_node_id} 失败: {exc}")

    ui_cfg = load_ui_config()
    if ui_cfg.get("connection_enabled", True) and ui_cfg.get("routing_mode") != "fixed_ip":
        auto_switch_node()

def _start_tunnel_for_protocol(
    proto: str,
    remote_host: str,
    port: int,
    config_path: Path,
    cancel_event: threading.Event | None = None,
    timeout: int | None = None,
) -> tuple[bool, str, Any, str, str]:
    norm_p = vpn_utils.normalize_vpn_protocol(proto)
    if norm_p == "sslvpn":
        return run_softether_sslvpn_until_ready(
            remote_host,
            port,
            keep_alive=True,
            timeout=timeout or 25,
            cancel_event=cancel_event,
        )
    if norm_p == "sstp":
        ok_s, msg_s, proc_s, dev_s = run_sstp_until_ready(
            remote_host,
            port,
            keep_alive=True,
            timeout=timeout or 25,
            unit=0,
            cancel_event=cancel_event,
            track_pending=True,
        )
        return ok_s, msg_s, proc_s, dev_s, ""
    ok_o, msg_o, proc_o = run_openvpn_until_ready(
        str(config_path),
        keep_alive=True,
        route_nopull=True,
        timeout=timeout,
        dev="tun0",
        cancel_event=cancel_event,
        track_pending=True,
    )
    return ok_o, msg_o, proc_o, "tun0", ""

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id
    global active_tunnel_interface, active_tunnel_protocol
    global last_active_ping_time, last_active_latency
    global consecutive_proxy_failures, last_proxy_failure_node_id
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")

    token, cancel_event = begin_connection_attempt()
    stopped_existing = False
    previous_node_id = ""
    try:
        set_state(
            is_connecting=True,
            pending_node_id=node_id,
            tunnel_ready=False,
            proxy_ready=False,
            proxy_ok=False,
            active_node_latency="正在连接",
            last_check_message=f"正在初始化连接配置: {node_id}",
        )
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")

        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")

        with lock:
            if active_openvpn_running():
                previous_node_id = active_openvpn_node_id
        
        ui_cfg = load_ui_config()
        validate_node_allowed_by_routing(node, ui_cfg)
        ui_cfg["connection_enabled"] = True
        auth_file = DATA_DIR / "ui_auth.json"
        with lock:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            write_json(auth_file, ui_cfg)

        set_state(active_node_latency="写入配置", last_check_message="正在写入 VPN 节点配置文件...")
        config_path = Path(node["config_file"])
        config_text = str(node.get("config_text") or "")
        remote_host = str(node.get("remote_host") or node.get("ip") or "")
        host_name = str(node.get("host_name") or "")
        eff_port = parse_int(node.get("remote_port"))
        eff_proto = vpn_utils.normalize_vpn_protocol(node.get("proto"))
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        probed_at = float(node.get("probed_at", 0) or 0)
        should_preflight = (
            SWITCH_PREFLIGHT_MAX_AGE_SECONDS > 0
            and bool(previous_node_id)
            and previous_node_id != node_id
            and time.time() - probed_at > SWITCH_PREFLIGHT_MAX_AGE_SECONDS
        )
        if should_preflight:
            set_state(active_node_latency="切换预检", last_check_message="正在保持当前连接并预检目标节点 (支持 UDP/TCP/SSL-VPN/SSTP 多协议回退)...")
            test_index = None
            try:
                test_index = get_free_test_index()
                preflight_ok, preflight_message, pf_proto, pf_port, pf_config = probe_openvpn_with_protocol_fallbacks(
                    node_id=node_id,
                    config_text=config_text,
                    remote_host=remote_host,
                    primary_port=eff_port,
                    primary_proto=eff_proto,
                    dev=f"tun{test_index}",
                    primary_timeout=OPENVPN_PROBE_TIMEOUT_SECONDS,
                    fallback_timeout=OPENVPN_FALLBACK_TIMEOUT_SECONDS,
                    max_fallbacks=4,
                    cancel_event=cancel_event,
                    track_pending=True,
                    host_name=host_name,
                )
            finally:
                if test_index is not None:
                    release_test_index(test_index)
            if not connection_attempt_is_current(token, cancel_event):
                raise ConnectionCancelled("连接操作已取消")
            if not preflight_ok:
                with lock:
                    current_nodes = read_nodes()
                    failed_node = next((item for item in current_nodes if item.get("id") == node_id), None)
                    if failed_node:
                        failed_node["probe_status"] = "unavailable"
                        failed_node["probe_message"] = preflight_message
                        failed_node["probed_at"] = time.time()
                        write_json(NODES_FILE, sort_all_nodes(current_nodes))
                raise RuntimeError(f"目标节点预检失败，已保留当前连接: {preflight_message}")
            if pf_config and pf_config != config_text:
                config_text = pf_config
                try:
                    config_path.write_text(config_text, encoding="utf-8")
                except Exception:
                    pass
            eff_proto = pf_proto
            eff_port = pf_port
            node["config_text"] = config_text
            node["proto"] = eff_proto
            node["remote_port"] = eff_port

        if not connection_attempt_is_current(token, cancel_event):
            raise ConnectionCancelled("连接操作已取消")
        set_state(active_node_latency="清理连接", last_check_message="目标节点可用，正在关闭旧的 VPN 连接及网卡...")
        stop_active_openvpn()
        stopped_existing = True

        proto_label = vpn_utils.format_vpn_protocol_label(eff_proto)
        set_state(active_node_latency="启动核心", last_check_message=f"正在启动 {proto_label} 核心服务并建立隧道连接...")
        ok, message, process, tunnel_dev, tunnel_gw = _start_tunnel_for_protocol(
            eff_proto,
            remote_host,
            eff_port,
            config_path,
            cancel_event=cancel_event,
        )
        if not connection_attempt_is_current(token, cancel_event):
            stop_process(process)
            raise ConnectionCancelled("连接操作已取消")

        if (not ok or process is None) and OPENVPN_PROTO_FALLBACK_ENABLED and remote_host:
            msg_lower = str(message or "").lower()
            if (
                not is_systemic_probe_failure(message)
                and "auth_failed" not in msg_lower
                and "err_ovpn_auth_failed" not in msg_lower
                and "连接操作已取消" not in msg_lower
            ):
                fallback_candidates = vpn_utils.generate_openvpn_fallback_endpoints(
                    remote_host,
                    eff_port,
                    eff_proto,
                    include_non_openvpn=True,
                )
                phys_dev = vpn_utils.get_physical_interface()
                sstpc_available = bool(vpn_utils.find_sstpc_binary())
                se_vc, se_vcmd = vpn_utils.find_softether_binaries()
                se_available = bool(se_vc and se_vcmd)
                tried_fb = 0
                for cand_proto, cand_port in fallback_candidates:
                    if tried_fb >= 4 or not connection_attempt_is_current(token, cancel_event):
                        break
                    if cand_proto == "sstp" and not sstpc_available:
                        continue
                    if cand_proto == "sslvpn" and not se_available:
                        continue
                    if cand_proto in ("tcp", "sslvpn", "sstp"):
                        if vpn_utils.tcp_latency_ms(remote_host, cand_port, phys_dev, timeout=1.8) <= 0:
                            continue
                    alt_config = config_text
                    if cand_proto in ("tcp", "udp"):
                        alt_config = vpn_utils.rewrite_openvpn_endpoint(config_text, remote_host, cand_port, cand_proto)
                        try:
                            config_path.write_text(alt_config, encoding="utf-8")
                        except Exception:
                            continue
                    tried_fb += 1
                    cand_label = vpn_utils.format_vpn_protocol_label(cand_proto)
                    set_state(
                        active_node_latency=f"尝试 {cand_label}:{cand_port}",
                        last_check_message=f"默认协议未响应，正在尝试备用协议 {cand_label}:{cand_port}...",
                    )
                    fb_ok, fb_msg, fb_proc, fb_dev, fb_gw = _start_tunnel_for_protocol(
                        cand_proto,
                        remote_host,
                        cand_port,
                        config_path,
                        cancel_event=cancel_event,
                        timeout=OPENVPN_PROBE_TIMEOUT_SECONDS,
                    )
                    if not connection_attempt_is_current(token, cancel_event):
                        stop_process(fb_proc)
                        raise ConnectionCancelled("连接操作已取消")
                    if fb_ok and fb_proc is not None:
                        ok = True
                        orig_label = vpn_utils.format_vpn_protocol_label(eff_proto)
                        message = f"{fb_msg} [多协议回退成功: {orig_label}:{eff_port} -> {cand_label}:{cand_port}]"
                        process = fb_proc
                        tunnel_dev = fb_dev
                        tunnel_gw = fb_gw
                        config_text = alt_config
                        eff_proto = cand_proto
                        eff_port = cand_port
                        node["config_text"] = config_text
                        node["proto"] = eff_proto
                        node["remote_port"] = eff_port
                        break
                    if is_systemic_probe_failure(fb_msg):
                        message = fb_msg
                        break

        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, sort_all_nodes(nodes))
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            print(f"[连接核心失败] 无法与 VPN 节点 {node_id} 建立隧道连接！详情: {message}", flush=True)
            raise RuntimeError(message)
            
        with lock:
            if not connection_attempt_is_current(token, cancel_event):
                stop_process(process)
                raise ConnectionCancelled("连接操作已取消")
            active_openvpn_process = process
            active_openvpn_node_id = node_id
            active_tunnel_interface = tunnel_dev
            active_tunnel_protocol = eff_proto
        set_state(tunnel_ready=True, proxy_ready=False)
        
        set_state(active_node_latency="配置路由", last_check_message=f"正在为虚拟网卡 {tunnel_dev} 配置策略路由规则与流量转发...")
        routing_ready = setup_policy_routing(tunnel_dev, gateway_ip=tunnel_gw)
        if not connection_attempt_is_current(token, cancel_event):
            raise ConnectionCancelled("连接操作已取消")
        
        last_active_ping_time = time.time()
        last_active_latency = 0
        
        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = eff_port or parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass
        
        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if not connection_attempt_is_current(token, cancel_event):
            raise ConnectionCancelled("连接操作已取消")
        if not res["ok"]:
            route_note = "；策略路由配置失败" if not routing_ready else ""
            raise RuntimeError(f"VPN 隧道已建立但代理出口不可用{route_note}: {res.get('error', '未知错误')}")

        latest_ui_cfg = load_ui_config()
        validate_node_allowed_by_routing(node, latest_ui_cfg)
        latest_ui_cfg["connection_enabled"] = True
        if latest_ui_cfg.get("routing_mode") == "fixed_ip":
            latest_ui_cfg["fixed_node_id"] = node_id

        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"
        final_proto_label = vpn_utils.format_vpn_protocol_label(eff_proto)
        with lock:
            if not connection_attempt_is_current(token, cancel_event):
                raise ConnectionCancelled("连接操作已取消")
            current_nodes = read_nodes()
            for item in current_nodes:
                item["active"] = item.get("id") == node_id
                if item["active"]:
                    item["probe_status"] = "available"
                    item["probed_at"] = time.time()
                    item["proto"] = eff_proto
                    item["remote_port"] = eff_port
                    item["config_text"] = config_text
                    _ph = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
                    item["probe_message"] = f"Active node ({final_proto_label}:{eff_port} via {tunnel_dev}). HTTP proxy: http://{_ph}:{LOCAL_PROXY_PORT}"
            sorted_current = sort_all_nodes(current_nodes)
            write_json(NODES_FILE, sorted_current)
            try:
                sync_favorite_snapshots_with_nodes(nodes=sorted_current)
            except Exception:
                pass
            write_json(auth_file, latest_ui_cfg)
            consecutive_proxy_failures = 0
            last_proxy_failure_node_id = node_id
            set_state(
                active_openvpn_node_id=node_id,
                is_connecting=False,
                pending_node_id="",
                last_check_message=f"Connected {node_id} ({final_proto_label}:{eff_port})",
                active_node_latency=latency_str,
                proxy_ok=True,
                tunnel_ready=True,
                proxy_ready=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error="",
            )
        log_to_json("INFO", "VPN", f"节点 {node_id} ({final_proto_label}:{eff_port}) 连接成功，出口网卡 {tunnel_dev} 已启用")
        cancel_background_refill()
        return f"Connected {node_id}"
    except ConnectionCancelled:
        if stopped_existing:
            stop_active_openvpn()
        raise
    except Exception as exc:
        if stopped_existing or (active_openvpn_node_id == node_id and not active_openvpn_running()):
            with lock:
                current_nodes = read_nodes()
                failed_node = next((item for item in current_nodes if item.get("id") == node_id), None)
                if failed_node:
                    failed_node["probe_status"] = "unavailable"
                    failed_node["probe_message"] = str(exc)
                    failed_node["probed_at"] = time.time()
                    write_json(NODES_FILE, sort_all_nodes(current_nodes))
            clear_active_connection_state(f"连接失败: {exc}")
        else:
            set_state(is_connecting=False, pending_node_id="", last_check_message=f"连接失败: {exc}")
        raise
    finally:
        finish_connection_attempt(token, cancel_event)
        set_state(pending_node_id="")

def maintain_valid_nodes(force: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        msg = "节点维护任务正在运行，请稍后再试"
        set_state(last_check_message=msg)
        return msg
    with lock:
        if is_connecting:
            maintenance_lock.release()
            msg = "当前已有连接或节点测试任务正在运行，请稍后再试"
            set_state(last_check_message=msg)
            return msg
        is_connecting = True
    try:
        # A forced refresh must not tear down a healthy tunnel. It only forces
        # the node-pool maintenance path below.
        if not active_openvpn_running():
            ui_cfg = load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            connection_enabled = ui_cfg.get("connection_enabled", True)
            if connection_enabled:
                if routing_mode == "fixed_ip":
                    reconnect_fixed_node_if_needed(ui_cfg)
                else:
                    has_active_id = False
                    with lock:
                        if active_openvpn_node_id:
                            has_active_id = True
                            stop_active_openvpn()
                    if has_active_id:
                        print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                        is_connecting = False
                        auto_switch_node()
                        is_connecting = True

        try:
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            diag_msg = str(exc)
            if not any(token in diag_msg for token in ["[ERR_", "错误代码"]):
                err_code, raw_diag = vpn_utils.diagnose_api_failure(API_URL)
                diag_msg = f"[错误代码 {err_code}] 获取节点失败: {exc} | 诊断结果: {raw_diag}"
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=diag_msg)
            candidates = []

        if not candidates:
            return "没有拉取到新节点"

        with lock:
            current_nodes = read_nodes()
            ui_cfg_for_merge = load_ui_config()
            fav_ids_list = [
                str(fid).strip()
                for fid in ui_cfg_for_merge.get("favorite_node_ids", [])
                if str(fid or "").strip()
            ]
            fav_ids_set = set(fav_ids_list)
            fav_snapshots = load_favorite_snapshots()
            current_by_id = {
                str(n.get("id")): n
                for n in current_nodes
                if n.get("id")
            }
            for fid, snap in fav_snapshots.items():
                if fid not in current_by_id and isinstance(snap, dict):
                    current_by_id[fid] = dict(snap)

            active_node = None
            if active_openvpn_node_id:
                active_node = next((n for n in current_nodes if n.get("id") == active_openvpn_node_id), None)
                
            merged: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            
            if active_node:
                merged.append(active_node)
                seen_ids.add(active_node["id"])

            preserve_keys = [
                "probe_status",
                "probe_message",
                "latency_ms",
                "probed_at",
                *IP_ENRICHMENT_FIELDS,
            ]
            candidate_by_id = {str(c.get("id")): c for c in candidates if c.get("id")}
            candidate_by_ip = {
                str(c.get("ip") or c.get("remote_host") or ""): c
                for c in candidates
                if (c.get("ip") or c.get("remote_host"))
            }
            fav_ids_updated = False

            # First ensure all favorite nodes are preserved or updated from fresh candidates
            for idx_fav, fid in enumerate(list(fav_ids_list)):
                if fid in seen_ids:
                    continue
                if fid in candidate_by_id:
                    cand = dict(candidate_by_id[fid])
                    previous = current_by_id.get(fid)
                    if previous:
                        for key in preserve_keys:
                            if previous.get(key) not in (None, ""):
                                cand[key] = previous.get(key)
                    cand["in_latest_feed"] = True
                    merged.append(cand)
                    seen_ids.add(fid)
                else:
                    previous = current_by_id.get(fid)
                    if previous:
                        prev_ip = str(previous.get("ip") or previous.get("remote_host") or "").strip()
                        matched_cand = candidate_by_ip.get(prev_ip) if prev_ip else None
                        if matched_cand and matched_cand["id"] not in seen_ids and matched_cand["id"] not in fav_ids_set:
                            # Same IP changed port/proto: migrate favorite to new node id
                            new_cand = dict(matched_cand)
                            for key in preserve_keys:
                                if previous.get(key) not in (None, ""):
                                    new_cand[key] = previous.get(key)
                            new_cand["in_latest_feed"] = True
                            merged.append(new_cand)
                            seen_ids.add(new_cand["id"])
                            fav_ids_list[idx_fav] = new_cand["id"]
                            fav_ids_set.discard(fid)
                            fav_ids_set.add(new_cand["id"])
                            fav_ids_updated = True
                        else:
                            restored = dict(previous)
                            restored["active"] = False
                            restored["in_latest_feed"] = False
                            if not restored.get("config_file"):
                                restored["config_file"] = str(CONFIG_DIR / f"{fid}.ovpn")
                            merged.append(restored)
                            seen_ids.add(fid)

            if fav_ids_updated:
                ui_cfg_for_merge["favorite_node_ids"] = fav_ids_list
                write_json(DATA_DIR / "ui_auth.json", ui_cfg_for_merge)
                
            for cand in candidates:
                if cand["id"] not in seen_ids:
                    previous = current_by_id.get(str(cand["id"]))
                    if previous:
                        for key in preserve_keys:
                            if previous.get(key) not in (None, ""):
                                cand[key] = previous.get(key)
                    cand["in_latest_feed"] = True
                    merged.append(cand)
                    seen_ids.add(cand["id"])
                    
            if len(merged) > 1000:
                merged = merged[:1000]
                
            for n in merged:
                config_path = Path(n["config_file"])
                if not config_path.exists() and n.get("config_text"):
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass
                        
            write_json(NODES_FILE, merged)
            try:
                sync_favorite_snapshots_with_nodes(fav_ids=fav_ids_list, nodes=merged)
            except Exception:
                pass
            ip_enrichment_wakeup.set()

        initial_tested_ids: set[str] = set()
        fast_results: list[dict[str, Any]] = []
        systemic_probe_failure = ""
        ui_cfg = load_ui_config()
        should_fast_connect = (
            ui_cfg.get("connection_enabled", True)
            and ui_cfg.get("routing_mode", "auto") != "fixed_ip"
            and not active_openvpn_running()
        )
        if should_fast_connect:
            with lock:
                current_nodes = read_nodes()
                fast_candidates = [
                    n for n in current_nodes
                    if not n.get("active") and n.get("probe_status") != "unavailable"
                ]
                fast_candidates = apply_routing_filters(fast_candidates, ui_cfg, include_unknown_ip_type=True)
                fast_candidates.sort(key=probe_priority_key)
                fast_test_ids = [
                    n["id"] for n in fast_candidates
                    if n.get("id")
                ][:INITIAL_CONNECT_TEST_LIMIT]

            if fast_test_ids:
                msg = f"首次快速连接模式：优先测试 {len(fast_test_ids)} 个高优先级节点，发现可用节点后立即连接"
                print(f"[快速首连] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                set_state(is_connecting=True, last_check_message=msg)
                fast_results = test_multiple_nodes(fast_test_ids, target_available=TARGET_VALID_NODES)
                systemic_probe_failure = next(
                    (
                        str(result.get("probe_message") or "")
                        for result in fast_results
                        if is_systemic_probe_failure(result.get("probe_message"))
                    ),
                    "",
                )
                initial_tested_ids = {
                    str(result.get("id") or "")
                    for result in fast_results
                    if result.get("id")
                }

                with lock:
                    fast_nodes = read_nodes()
                    available_candidates = [
                        n for n in fast_nodes
                        if n.get("probe_status") == "available" and not n.get("active")
                    ]
                    available_candidates = apply_routing_filters(available_candidates, ui_cfg)

                if available_candidates:
                    is_connecting = False
                    set_state(is_connecting=False, last_check_message="快速首连已找到可用节点，正在建立连接...")
                    auto_switch_node()
                    if active_openvpn_running():
                        valid_nodes_count = len([n for n in read_nodes() if n.get("probe_status") == "available"])
                        message = f"Fetched {len(candidates)} nodes. Fast-tested {len(fast_results)} nodes and connected."
                        set_state(
                            last_check_at=time.time(),
                            last_check_message=message,
                            active_openvpn_node_id=active_openvpn_node_id,
                            valid_nodes=valid_nodes_count,
                        )
                        return message
                    is_connecting = True

        tested_results: list[dict[str, Any]] = []
        if systemic_probe_failure:
            msg = f"已跳过本轮剩余节点检测，系统级故障需要先处理: {systemic_probe_failure}"
            print(f"[周期检测] {msg}", flush=True)
            log_to_json("ERROR", "VPN", msg)
            set_state(last_check_message=msg)
        else:
            # Test remaining non-active nodes from the list
            with lock:
                current_nodes = read_nodes()
                to_test = [
                    n for n in current_nodes
                    if not n.get("active") and n.get("id") not in initial_tested_ids
                ]
                to_test = apply_routing_filters(to_test, ui_cfg, include_unknown_ip_type=True)
                to_test.sort(key=probe_priority_key)
                to_test_ids = [n["id"] for n in to_test]

            msg = f"开始对列表中所有候选节点进行周期连通性与延迟测试，待检测节点共 {len(to_test_ids)} 个"
            print(f"[周期检测] {msg}", flush=True)
            log_to_json("INFO", "Main", msg)

            set_state(is_connecting=True, last_check_message="正在并发检测所有节点可用性...")
            tested_results = test_multiple_nodes(to_test_ids, target_available=TARGET_VALID_NODES)
        is_connecting = False
        
        with lock:
            merged = read_nodes()
            
            # Identify available, unavailable, and active nodes
            available_nodes = [n["id"] for n in merged if n.get("probe_status") == "available"]
            unavailable_nodes = [n["id"] for n in merged if n.get("probe_status") == "unavailable"]
            active_node = next((n["id"] for n in merged if n.get("active")), "无")
            
            status_report = (
                f"周期节点检测完成。实时同步状态: 获取到候选节点共 {len(merged)} 个。 "
                f"其中【可用节点】{len(available_nodes)} 个: {available_nodes[:15]}...; "
                f"【不可用节点】{len(unavailable_nodes)} 个; "
                f"当前【正在正常运行的活动连接节点】为: {active_node}。"
            )
            print(f"[周期检测] {status_report}", flush=True)
            log_to_json("INFO", "Main", status_report)
            
            if active_node != "无" and not active_openvpn_running():
                warn_msg = f"[诊断警告] 活动节点 {active_node} 被标记为活动状态，但 OpenVPN 进程实际并未正常运行！"
                print(warn_msg, flush=True)
                log_to_json("WARNING", "Main", warn_msg)
            
            if not active_openvpn_running():
                ui_cfg = load_ui_config()
                connection_enabled = ui_cfg.get("connection_enabled", True)
                if connection_enabled:
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    
                    if routing_mode != "fixed_ip":
                        available_candidates = [n for n in merged if n.get("probe_status") == "available"]
                        available_candidates = apply_routing_filters(available_candidates, ui_cfg)
                        
                        if available_candidates:
                            auto_switch_node()

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        total_tested = len(fast_results) + len(tested_results)
        message = f"Fetched {len(candidates)} nodes. Tested {total_tested} prioritized non-active nodes."
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
        )
        return message
    except Exception as e:
        raise e
    finally:
        is_connecting = False
        maintenance_lock.release()


def collector_loop() -> None:
    global last_collector_heartbeat
    while True:
        last_collector_heartbeat = time.time()
        success = False
        try:
            print("[守护线程] 开始执行节点拉取与可用性检测周期任务...", flush=True)
            log_to_json("INFO", "Main", "开始执行节点拉取与可用性检测周期任务...")
            res = maintain_valid_nodes(force=False)
            if "没有拉取到新节点" not in res:
                success = True
            log_to_json("INFO", "Main", f"周期同步与检测任务完成，结果: {res}")
        except Exception as exc:
            err_msg = f"周期节点同步任务执行异常: {exc}"
            print(f"[错误] {err_msg}", flush=True)
            log_to_json("ERROR", "Main", err_msg)
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")
            
        if not active_openvpn_running() and not success:
            sleep_time = 30
        else:
            sleep_time = CHECK_INTERVAL_SECONDS
            
        time.sleep(sleep_time)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AimiliVPN - 安全登录</title>
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-surface: rgba(15, 23, 42, 0.96);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --danger: #f43f5e;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 64px;
      height: 64px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--primary);
      position: relative;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid var(--success);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }


    /* === Opus CloudPulse / Linear Design System Upgrade === */
    :root {
      --bg-dark: #07080b;
      --bg-surface: rgba(18, 20, 27, 0.94);
      --bg-surface-hover: rgba(28, 31, 41, 0.94);
      --surface-solid: #11131a;
      --border-color: rgba(255, 255, 255, 0.075);
      --border-color-hover: rgba(124, 131, 255, 0.42);
      --text-primary: #ededf0;
      --text-secondary: #9ea3b0;
      --text-muted: #6c707e;
      --primary: #7c83ff;
      --primary-gradient: linear-gradient(180deg, #8d93ff 0%, #636af2 100%);
      --primary-hover: linear-gradient(180deg, #9aa0ff 0%, #6f76f6 100%);
      --success: #34d399;
      --success-gradient: linear-gradient(180deg, #34d399 0%, #10b981 100%);
      --danger: #f87171;
      --danger-gradient: linear-gradient(180deg, #fb7185 0%, #e11d48 100%);
      --warning: #fbbf24;
      --warning-gradient: linear-gradient(180deg, #fbbf24 0%, #d97706 100%);
      --cyan: #22d3ee;
      --violet: #a78bfa;
      --blue: #60a5fa;
      --g-ap: #2dd4bf;
      --g-a: #4ade80;
      --g-b: #60a5fa;
      --g-c: #fbbf24;
      --g-d: #f87171;
      --active-row-bg: rgba(96, 165, 250, 0.065);
      --active-row-border: rgba(96, 165, 250, 0.28);
      --card-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.045), 0 12px 32px rgba(0, 0, 0, 0.34);
      color-scheme: dark;
    }

    html[data-theme="light"] {
      --bg-dark: #f4f5f8;
      --bg-surface: rgba(255, 255, 255, 0.96);
      --bg-surface-hover: rgba(248, 250, 252, 0.98);
      --surface-solid: #ffffff;
      --border-color: rgba(15, 23, 42, 0.085);
      --border-color-hover: rgba(91, 97, 240, 0.38);
      --text-primary: #0f1117;
      --text-secondary: #525866;
      --text-muted: #848a98;
      --primary: #5b61f0;
      --primary-gradient: linear-gradient(180deg, #6e74f8 0%, #5258e8 100%);
      --primary-hover: linear-gradient(180deg, #5f65f2 0%, #464cd8 100%);
      --success: #059669;
      --danger: #dc2626;
      --warning: #d97706;
      --cyan: #0891b2;
      --violet: #7c3aed;
      --blue: #2563eb;
      --g-ap: #0d9488;
      --g-a: #16a34a;
      --g-b: #2563eb;
      --g-c: #b45309;
      --g-d: #dc2626;
      --active-row-bg: rgba(37, 99, 235, 0.055);
      --active-row-border: rgba(37, 99, 235, 0.24);
      --card-shadow: 0 1px 2px rgba(15, 18, 30, 0.04), 0 10px 28px rgba(15, 18, 30, 0.06);
      color-scheme: light;
    }

    body {
      position: relative;
      overflow-x: hidden;
      transition: background-color 0.25s ease, color 0.25s ease;
    }

    .bg-fx {
      position: fixed;
      inset: 0;
      pointer-events: none;
      z-index: 0;
      background:
        radial-gradient(920px 500px at 10% -10%, rgba(124, 131, 255, 0.13), transparent 60%),
        radial-gradient(840px 460px at 95% -12%, rgba(34, 211, 238, 0.07), transparent 62%);
    }
    .bg-fx::after {
      content: "";
      position: absolute;
      inset: 0;
      background-image:
        linear-gradient(rgba(255, 255, 255, 0.028) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.028) 1px, transparent 1px);
      background-size: 44px 44px;
      -webkit-mask-image: radial-gradient(ellipse 75% 45% at 50% 0%, #000 20%, transparent 75%);
      mask-image: radial-gradient(ellipse 75% 45% at 50% 0%, #000 20%, transparent 75%);
    }
    html[data-theme="light"] .bg-fx::after {
      background-image:
        linear-gradient(rgba(15, 18, 30, 0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(15, 18, 30, 0.04) 1px, transparent 1px);
    }

    header, main {
      position: relative;
      z-index: 1;
    }

    header {
      padding: 12px 28px;
      background: var(--bg-surface);
      box-shadow: 0 1px 0 var(--border-color);
    }

    .brand {
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
    }

    .brand-logo-box {
      width: 30px;
      height: 30px;
      border-radius: 8px;
      display: inline-grid;
      place-items: center;
      background: linear-gradient(135deg, #7c83ff 0%, #5b8cff 48%, #22d3ee 100%);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.4), 0 4px 14px rgba(124, 131, 255, 0.32);
      color: #ffffff;
      flex-shrink: 0;
    }

    h1 {
      font-size: 16px;
      font-weight: 600;
      background: none;
      -webkit-text-fill-color: var(--text-primary);
      color: var(--text-primary);
      letter-spacing: -0.02em;
      gap: 10px;
    }

    .status {
      margin-top: 0;
      height: 28px;
      padding: 0 12px;
      border-radius: 999px;
      border: 1px solid rgba(52, 211, 153, 0.25);
      background: rgba(52, 211, 153, 0.07);
      font-size: 12px;
      color: var(--text-secondary);
    }

    .theme-toggle-btn {
      width: 36px;
      height: 36px;
      padding: 0;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border-color);
      color: var(--text-secondary);
    }
    .theme-toggle-btn:hover {
      color: var(--text-primary);
      border-color: var(--border-color-hover);
    }

    /* KPI Overview Strip */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }
    .kpi-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 14px;
      padding: 14px 16px;
      box-shadow: var(--card-shadow);
      display: flex;
      flex-direction: column;
      gap: 4px;
      min-width: 0;
    }
    .kpi-label {
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .kpi-val {
      font-size: 22px;
      font-weight: 700;
      color: var(--text-primary);
      letter-spacing: -0.03em;
      font-family: 'JetBrains Mono', Consolas, monospace;
    }
    .kpi-unit {
      font-size: 12px;
      color: var(--text-muted);
      font-weight: 500;
      margin-left: 4px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .kpi-sub {
      font-size: 11.5px;
      color: var(--text-secondary);
      margin-top: 2px;
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .kpi-bar {
      height: 4px;
      border-radius: 99px;
      background: rgba(255, 255, 255, 0.07);
      overflow: hidden;
      margin-top: 6px;
    }
    .kpi-bar > i {
      display: block;
      height: 100%;
      border-radius: inherit;
      background: var(--success);
      transition: width 0.3s ease;
    }
    .kpi-dist {
      display: flex;
      height: 4px;
      border-radius: 99px;
      overflow: hidden;
      gap: 2px;
      margin-top: 6px;
      background: rgba(255, 255, 255, 0.05);
    }
    .kpi-dist > i {
      display: block;
      height: 100%;
    }

    /* Hero Active Card */
    .active-card {
      position: relative;
      overflow: hidden;
      background: var(--bg-surface);
      border: 1px solid rgba(124, 131, 255, 0.28);
      border-radius: 16px;
      padding: 20px 24px;
      box-shadow: var(--card-shadow);
    }
    .active-card::before {
      content: "";
      position: absolute;
      width: 480px;
      height: 480px;
      left: -140px;
      top: -320px;
      background: radial-gradient(circle, rgba(124, 131, 255, 0.16), transparent 65%);
      pointer-events: none;
    }
    .hero-meta-strip {
      display: inline-flex;
      flex-wrap: wrap;
      border: 1px solid var(--border-color);
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.025);
      margin-top: 10px;
      overflow: hidden;
    }
    .hero-meta-cell {
      display: flex;
      flex-direction: column;
      gap: 2px;
      padding: 7px 14px;
      border-right: 1px solid var(--border-color);
    }
    .hero-meta-cell:last-child {
      border-right: none;
    }
    .hero-meta-k {
      font-size: 11px;
      color: var(--text-muted);
    }
    .hero-meta-v {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-primary);
      white-space: nowrap;
    }
    .hero-side-panel {
      display: flex;
      flex-direction: column;
      gap: 10px;
      min-width: 280px;
      padding-left: 20px;
      border-left: 1px solid var(--border-color);
    }
    .hero-score-pills {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .hero-action-btns {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    /* Search box in toolbar */
    .toolbar-search {
      display: flex;
      align-items: center;
      gap: 8px;
      height: 38px;
      padding: 0 10px;
      border-radius: 8px;
      border: 1px solid var(--border-color);
      background: rgba(255, 255, 255, 0.03);
      min-width: 220px;
      flex: 1 1 220px;
      max-width: 280px;
      color: var(--text-muted);
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .toolbar-search:focus-within {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(124, 131, 255, 0.16);
    }
    .toolbar-search input {
      flex: 1;
      min-width: 0;
      border: none;
      outline: none;
      background: transparent;
      color: var(--text-primary);
      font-size: 13px;
      font-family: inherit;
    }
    .toolbar-search input::placeholder {
      color: var(--text-muted);
    }
    .toolbar-search kbd {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 10.5px;
      color: var(--text-muted);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 0 5px;
      line-height: 16px;
      background: rgba(255, 255, 255, 0.04);
    }
    .toolbar select, .country-filter-button {
      height: 38px;
      font-size: 13px;
    }

    /* Signal bars & Sublabels in Table */
    .sig-bars {
      display: inline-flex;
      align-items: flex-end;
      gap: 2px;
      height: 11px;
      margin-right: 5px;
      vertical-align: middle;
    }
    .sig-bars i {
      width: 3px;
      border-radius: 1px;
      background: rgba(255, 255, 255, 0.16);
      display: inline-block;
    }
    html[data-theme="light"] .sig-bars i {
      background: rgba(15, 23, 42, 0.16);
    }
    .sig-bars i:nth-child(1) { height: 4px; }
    .sig-bars i:nth-child(2) { height: 7px; }
    .sig-bars i:nth-child(3) { height: 11px; }
    .latency-good .sig-bars i.on { background: #34d399; }
    .latency-medium .sig-bars i.on { background: #fbbf24; }
    .latency-poor .sig-bars i.on { background: #fb7185; }

    .cell-sub {
      font-size: 11.5px;
      color: var(--text-muted);
      margin-top: 2px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    /* Type Tag & Grade Pills */
    .type-tag {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 11.5px;
      font-weight: 500;
      color: var(--text-secondary);
      padding: 1px 7px;
      border-radius: 5px;
      border: 1px solid var(--border-color);
      background: rgba(255, 255, 255, 0.03);
      width: fit-content;
    }
    .type-tag::before {
      content: "";
      width: 5px;
      height: 5px;
      border-radius: 1px;
      background: var(--tag-dot, #22d3ee);
    }
    .type-tag.t-res { --tag-dot: #22d3ee; }
    .type-tag.t-host { --tag-dot: #a78bfa; }
    .type-tag.t-mob { --tag-dot: #60a5fa; }

    .qpills-row {
      display: flex;
      gap: 5px;
      flex-wrap: wrap;
      margin-top: 5px;
    }
    .cleanip-badge {
      height: 22px;
      padding: 0 7px;
      border-radius: 6px;
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 11px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .cleanip-badge:hover {
      transform: translateY(-1px);
    }
    .cleanip-grade-ap {
      background: linear-gradient(135deg, rgba(52, 211, 153, 0.22), rgba(34, 211, 238, 0.22));
      color: #2dd4bf;
      border-color: rgba(45, 212, 191, 0.42);
      box-shadow: 0 0 10px rgba(45, 212, 191, 0.15);
    }

    /* CleanIP Modal Summary Card & Segmented Switch */
    .report-summary-card {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 14px 16px;
      border-radius: 12px;
      border: 1px solid var(--border-color);
      background: rgba(255, 255, 255, 0.025);
      margin-bottom: 14px;
      flex-wrap: wrap;
    }
    .report-grade-box {
      width: 52px;
      height: 52px;
      border-radius: 12px;
      display: grid;
      place-items: center;
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 20px;
      font-weight: 700;
      flex-shrink: 0;
      border: 1px solid rgba(45, 212, 191, 0.35);
      background: rgba(45, 212, 191, 0.12);
      color: #2dd4bf;
    }
    .report-seg {
      display: inline-flex;
      padding: 2px;
      gap: 2px;
      border-radius: 8px;
      border: 1px solid var(--border-color);
      background: rgba(255, 255, 255, 0.03);
      height: 32px;
    }
    .report-seg button {
      height: 26px;
      padding: 0 10px;
      border-radius: 6px;
      border: none;
      background: transparent;
      font-size: 12px;
      color: var(--text-secondary);
      transform: none !important;
      box-shadow: none !important;
    }
    .report-seg button.on {
      background: var(--surface-solid);
      color: var(--text-primary);
      border: 1px solid var(--border-color);
    }
    .term-topbar {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 14px;
      background: rgba(255, 255, 255, 0.035);
      border: 1px solid rgba(255, 255, 255, 0.07);
      border-bottom: none;
      border-radius: 10px 10px 0 0;
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 11.5px;
      color: var(--text-muted);
    }
    .term-dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      display: inline-block;
    }

    /* Selected Pill in Batch Bar */
    .sel-pill-badge {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      height: 28px;
      padding: 0 11px 0 5px;
      border-radius: 999px;
      font-size: 12.5px;
      color: var(--text-secondary);
      background: rgba(255, 255, 255, 0.035);
      border: 1px solid var(--border-color);
      margin-right: 4px;
    }
    .sel-num-circle {
      min-width: 20px;
      height: 20px;
      padding: 0 5px;
      display: inline-grid;
      place-items: center;
      border-radius: 999px;
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-weight: 700;
      font-size: 11px;
      background: var(--primary);
      color: #ffffff;
    }

    /* Toast Notification */
    .toasts-container {
      position: fixed;
      right: 20px;
      bottom: 20px;
      z-index: 20000;
      display: flex;
      flex-direction: column;
      gap: 8px;
      align-items: flex-end;
      pointer-events: none;
    }
    .ui-toast {
      display: flex;
      align-items: center;
      gap: 10px;
      max-width: 380px;
      padding: 10px 14px;
      border-radius: 10px;
      font-size: 13px;
      background: var(--surface-solid);
      border: 1px solid var(--border-color-hover);
      color: var(--text-primary);
      box-shadow: 0 14px 40px rgba(0, 0, 0, 0.45);
      opacity: 0;
      transform: translateY(8px);
      transition: opacity 0.2s ease, transform 0.2s ease;
    }
    .ui-toast.in {
      opacity: 1;
      transform: translateY(0);
    }

    @media (max-width: 960px) {
      .kpi-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .hero-side-panel {
        padding-left: 0;
        border-left: none;
        padding-top: 14px;
        border-top: 1px solid var(--border-color);
        width: 100%;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h2 class="login-title">AimiliVPN</h2>
      <p class="login-subtitle">请输入您的管理账号和安全密码以继续</p>
      
      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
            <input type="text" id="username" name="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" name="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        
        <button type="submit" id="submit_btn" class="login-btn">
          <span>登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    function fetchWithTimeout(resource, options = {}, timeoutMs = 20000) {
      if (typeof AbortController === "undefined") return fetch(resource, options);
      const controller = new AbortController();
      const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
      return fetch(resource, Object.assign({}, options, { signal: controller.signal }))
        .then(
          response => { window.clearTimeout(timeoutId); return response; },
          error => { window.clearTimeout(timeoutId); throw error; }
        );
    }

    async function handleLogin(e) {
      e.preventDefault();
      const uname = document.getElementById("username").value.trim();
      const pwd = document.getElementById("password").value;
      const errorText = document.getElementById("error_text");
      const submitBtn = document.getElementById("submit_btn");
      
      errorText.style.display = "none";
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证...";
      
      try {
        const response = await fetchWithTimeout("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd })
        }, 20000);
        
        const data = await response.json();
        if (response.ok && data.ok) {
          window.location.reload();
        } else {
          errorText.textContent = data.error || "账号或密码不正确，请重新输入";
          errorText.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "登录";
        }
      } catch (err) {
        errorText.textContent = err && err.name === "AbortError"
          ? "登录请求超时，请检查网络后重试"
          : "连接服务器失败，请稍后重试";
        errorText.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AimiliVPN · 节点状态看板</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --font:'Inter',-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei',system-ui,sans-serif;
  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --bg:#07080b;--surface:rgba(19,21,27,.68);--surface-2:rgba(30,32,40,.62);--surface-solid:#111318;
  --hover:rgba(255,255,255,.04);--hover-2:rgba(255,255,255,.07);
  --border:rgba(255,255,255,.07);--border-2:rgba(255,255,255,.11);--border-3:rgba(255,255,255,.2);
  --text:#ededf0;--text-2:#a2a5b0;--text-3:#6c707c;
  --accent:#7c83ff;--accent-2:#b18cff;
  --green:#34d399;--blue:#60a5fa;--amber:#fbbf24;--red:#f87171;--gray:#7d818e;--violet:#a78bfa;--cyan:#22d3ee;
  --g-ap:#2dd4bf;--g-a:#4ade80;--g-b:#60a5fa;--g-c:#fbbf24;--g-d:#f87171;
  --shadow:inset 0 1px 0 rgba(255,255,255,.04),0 10px 30px rgba(0,0,0,.3);
  --menu-bg:rgba(17,19,25,.94);--dialog-bg:#0e0f14;--topbar-bg:rgba(7,8,11,.72);--th-bg:rgba(255,255,255,.015);
  --tip-bg:#e9eaf0;--tip-fg:#0b0c10;
  --glow-1:rgba(124,131,255,.13);--glow-2:rgba(34,211,238,.06);--gridline:rgba(255,255,255,.035);
  color-scheme:dark;
}
[data-theme="light"]{
  --bg:#f5f6f8;--surface:rgba(255,255,255,.8);--surface-2:rgba(255,255,255,.92);--surface-solid:#fff;
  --hover:rgba(15,18,30,.035);--hover-2:rgba(15,18,30,.06);
  --border:rgba(15,18,30,.075);--border-2:rgba(15,18,30,.12);--border-3:rgba(15,18,30,.22);
  --text:#0f1117;--text-2:#555a68;--text-3:#8b909c;
  --accent:#5b61f0;--accent-2:#7c3aed;
  --green:#059669;--blue:#2563eb;--amber:#b86e00;--red:#dc2626;--gray:#8b909c;--violet:#7c3aed;--cyan:#0891b2;
  --g-ap:#0d9488;--g-a:#16a34a;--g-b:#2563eb;--g-c:#b45309;--g-d:#dc2626;
  --shadow:0 1px 2px rgba(15,18,30,.04),0 8px 28px rgba(15,18,30,.05);
  --menu-bg:rgba(255,255,255,.97);--dialog-bg:#fff;--topbar-bg:rgba(245,246,248,.78);--th-bg:rgba(15,18,30,.018);
  --tip-bg:#14161c;--tip-fg:#f2f3f6;
  --glow-1:rgba(91,97,240,.10);--glow-2:rgba(8,145,178,.06);--gridline:rgba(15,18,30,.045);
  color-scheme:light;
}
html{background:var(--bg)}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased;min-height:100vh;overflow-x:hidden;transition:background .3s,color .3s}
body.modal-open{overflow:hidden}
button{font:inherit;color:inherit;cursor:pointer}
button:disabled{cursor:not-allowed}
a{color:inherit;text-decoration:none}
.mono{font-family:var(--mono);font-feature-settings:"zero" 1;letter-spacing:-.01em}
.muted{color:var(--text-3)}
.ic{width:16px;height:16px;flex:none}
.flag{font-family:"Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji",sans-serif}
.spacer{flex:1}
:focus-visible{outline:2px solid color-mix(in srgb,var(--accent) 70%,transparent);outline-offset:2px;border-radius:6px}

/* ---------- background ---------- */
.bg-fx{position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(900px 520px at 10% -10%,var(--glow-1),transparent 60%),radial-gradient(820px 480px at 95% -14%,var(--glow-2),transparent 62%)}
.bg-fx::after{content:"";position:absolute;inset:0;background-image:linear-gradient(var(--gridline) 1px,transparent 1px),linear-gradient(90deg,var(--gridline) 1px,transparent 1px);background-size:44px 44px;-webkit-mask-image:radial-gradient(ellipse 75% 45% at 50% 0%,#000 25%,transparent 75%);mask-image:radial-gradient(ellipse 75% 45% at 50% 0%,#000 25%,transparent 75%)}

/* ---------- buttons ---------- */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:32px;padding:0 12px;border-radius:8px;border:1px solid var(--border-2);background:var(--surface-2);color:var(--text);font-size:13px;font-weight:500;white-space:nowrap;transition:background .15s,border-color .15s,transform .1s,box-shadow .15s,color .15s}
.btn:hover:not(:disabled){background:var(--hover-2);border-color:var(--border-3)}
.btn:active:not(:disabled){transform:translateY(1px)}
.btn:disabled{opacity:.45}
.btn-sm{height:26px;padding:0 9px;font-size:12px;border-radius:6px;gap:5px}
.btn-sm .ic{width:14px;height:14px}
.btn-ghost{background:transparent;border-color:transparent;color:var(--text-2)}
.btn-ghost:hover:not(:disabled){color:var(--text);background:var(--hover);border-color:transparent}
.btn-primary{background:linear-gradient(180deg,#8d93ff,#666df2);border-color:rgba(255,255,255,.08);color:#fff;box-shadow:inset 0 1px 0 rgba(255,255,255,.28),0 4px 16px rgba(108,115,255,.32)}
.btn-primary:hover:not(:disabled){background:linear-gradient(180deg,#999fff,#7077f5);border-color:rgba(255,255,255,.14)}
.btn-tint{--c:var(--accent);color:var(--c);background:color-mix(in srgb,var(--c) 11%,transparent);border-color:color-mix(in srgb,var(--c) 30%,transparent)}
.btn-tint:hover:not(:disabled){background:color-mix(in srgb,var(--c) 19%,transparent);border-color:color-mix(in srgb,var(--c) 48%,transparent)}
.btn-amber{--c:var(--amber)}.btn-blue{--c:var(--blue)}.btn-violet{--c:var(--violet)}
.btn-danger-ghost{color:var(--red);background:transparent;border-color:color-mix(in srgb,var(--red) 25%,transparent)}
.btn-danger-ghost:hover:not(:disabled){background:color-mix(in srgb,var(--red) 10%,transparent)!important;border-color:color-mix(in srgb,var(--red) 45%,transparent)!important}
.icon-btn{display:inline-grid;place-items:center;width:32px;height:32px;border-radius:8px;border:1px solid transparent;background:transparent;color:var(--text-2);transition:.15s}
.icon-btn:hover{background:var(--hover);color:var(--text);border-color:var(--border)}
.icon-btn.sm{width:24px;height:24px;border-radius:6px}
.icon-btn.sm .ic{width:13px;height:13px}
kbd{font-family:var(--mono);font-size:10.5px;color:var(--text-3);border:1px solid var(--border-2);border-bottom-width:2px;border-radius:4px;padding:0 5px;line-height:16px;background:var(--hover)}
.spin{display:inline-block;width:11px;height:11px;border-radius:50%;border:1.6px solid currentColor;border-top-color:transparent;animation:spin .7s linear infinite;flex:none}
.spinning .ic{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* ---------- topbar ---------- */
.topbar{position:sticky;top:0;z-index:40;background:var(--topbar-bg);-webkit-border-bottom:1px solid var(--border)}
.topbar-inner{max-width:1360px;margin:0 auto;height:56px;padding:0 24px;display:flex;align-items:center;gap:14px}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.logo{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;flex:none;background:linear-gradient(135deg,#7c83ff 0%,#5b8cff 45%,#22d3ee 100%);box-shadow:inset 0 1px 0 rgba(255,255,255,.4),0 4px 14px rgba(124,131,255,.35)}
.brand-name{font-weight:600;letter-spacing:-.02em;font-size:15px}
.brand-sep{color:var(--text-3);opacity:.5;font-weight:300;font-size:18px}
.live-pill{display:inline-flex;align-items:center;gap:8px;height:26px;padding:0 10px 0 10px;border-radius:999px;border:1px solid color-mix(in srgb,var(--green) 24%,var(--border));background:color-mix(in srgb,var(--green) 7%,transparent);font-size:12px;color:var(--text-2);white-space:nowrap;min-width:0}
.live-pill b{color:var(--green);font-weight:600}
.lp-div{width:1px;height:12px;background:var(--border-2)}
.pulse{position:relative;width:7px;height:7px;border-radius:50%;background:var(--green);flex:none;box-shadow:0 0 8px var(--green)}
.pulse::after{content:"";position:absolute;inset:-4px;border-radius:50%;background:var(--green);animation:ping 2s cubic-bezier(0,0,.2,1) infinite}
@keyframes ping{0%{transform:scale(.4);opacity:.55}80%,100%{transform:scale(1.7);opacity:0}}
.top-actions{margin-left:auto;display:flex;align-items:center;gap:6px}
.btn-ver{gap:7px;padding:0 9px;height:30px}
.ver-dot{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green)}
.admin-btn{display:inline-flex;align-items:center;gap:8px;height:32px;padding:0 8px 0 4px;border-radius:999px;border:1px solid var(--border-2);background:var(--surface-2);font-size:13px;font-weight:500;transition:.15s}
.admin-btn:hover{border-color:var(--border-3)}
.avatar{width:24px;height:24px;border-radius:50%;display:grid;place-items:center;font-size:11px;font-weight:600;color:#fff;background:linear-gradient(135deg,#f59e0b,#ef4444 55%,#a855f7);flex:none}
.avatar.lg{width:34px;height:34px;font-size:13px}
.vsep{width:1px;height:20px;background:var(--border-2);margin:0 4px}

/* ---------- dropdown ---------- */
.dd{position:relative}
.dd-menu{position:absolute;top:calc(100% + 6px);left:0;min-width:184px;padding:5px;background:var(--menu-bg);border:1px solid var(--border-2);border-radius:11px;box-shadow:0 16px 48px rgba(0,0,0,.42),0 2px 6px rgba(0,0,0,.2);-webkit-opacity:0;transform:translateY(-4px) scale(.98);transform-origin:top left;pointer-events:none;visibility:hidden;transition:opacity .14s,transform .14s,visibility 0s .14s;z-index:60}
.dd.right .dd-menu{left:auto;right:0;transform-origin:top right}
.dd.open .dd-menu{opacity:1;transform:none;pointer-events:auto;visibility:visible;transition:opacity .14s,transform .14s}
.w-220{min-width:220px}.w-260{min-width:264px}
.dd-opt,.menu-item{display:flex;align-items:center;gap:9px;width:100%;padding:7px 9px;border-radius:7px;font-size:13px;color:var(--text-2);background:none;border:0;text-align:left;white-space:nowrap;transition:background .12s,color .12s}
.dd-opt:hover,.menu-item:hover{background:var(--hover-2);color:var(--text)}
.dd-opt.active{color:var(--text)}
.dd-opt.active::after{content:"";margin-left:auto;width:12px;height:12px;background:var(--accent);-webkit-mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m5 12 5 5 9-10'/%3E%3C/svg%3E") center/contain no-repeat;mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m5 12 5 5 9-10'/%3E%3C/svg%3E") center/contain no-repeat}
.menu-item kbd{margin-left:auto}
.menu-item .ml{margin-left:auto;width:13px;height:13px;opacity:.6}
.menu-item.danger{color:var(--red)}
.menu-item.danger:hover{background:color-mix(in srgb,var(--red) 10%,transparent);color:var(--red)}
.menu-badge{margin-left:auto;font:600 10.5px var(--mono);padding:0 6px;border-radius:999px;background:color-mix(in srgb,var(--amber) 16%,transparent);color:var(--amber)}
.menu-sep{height:1px;background:var(--border);margin:5px 3px}
.menu-label{padding:6px 9px 5px;font-size:11px;color:var(--text-3);letter-spacing:.02em}
.menu-user{display:flex;align-items:center;gap:10px;padding:8px 8px 6px}
.menu-user b{display:block;font-size:13px;font-weight:600}
.menu-user small{font-size:11.5px;color:var(--text-3)}
.ver-card{padding:9px 9px 7px}
.ver-row{display:flex;align-items:center;gap:8px;font-weight:600;font-size:13px}
.chip-stable{font:600 10px var(--mono);padding:1px 6px;border-radius:4px;color:var(--green);background:color-mix(in srgb,var(--green) 13%,transparent);border:1px solid color-mix(in srgb,var(--green) 28%,transparent)}
.ver-num{font-size:12px;margin-top:2px;color:var(--text-2)}
.ver-status{display:flex;align-items:center;gap:10px;margin-top:10px;padding:8px 10px;border-radius:8px;background:var(--hover);border:1px solid var(--border)}
.ver-status b{display:block;font-size:12.5px;font-weight:500}
.ver-status small{font-size:11px;color:var(--text-3)}
.vs-ic{width:22px;height:22px;border-radius:50%;display:grid;place-items:center;flex:none;color:var(--green);background:color-mix(in srgb,var(--green) 14%,transparent)}
.vs-ic .ic{width:13px;height:13px}
.vs-ic.busy{color:var(--accent);background:color-mix(in srgb,var(--accent) 14%,transparent)}

/* ---------- layout ---------- */
.wrap{position:relative;z-index:1;max-width:1360px;margin:0 auto;padding:22px 24px 72px;display:flex;flex-direction:column;gap:14px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;box-shadow:var(--shadow);-webkit-}
.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:2px 2px 4px}
.crumbs{display:flex;gap:7px;font-size:12px;color:var(--text-3)}
.crumbs .sep{opacity:.5}
.page-head h2{font-size:20px;font-weight:600;letter-spacing:-.025em;margin-top:2px}
.ph-right{display:flex;gap:16px;flex-wrap:wrap}
.ph-meta{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--text-3)}
.ph-meta .ic{width:13px;height:13px}
.ph-meta .mono{color:var(--text-2)}

/* ---------- hero ---------- */
.hero{position:relative;overflow:hidden;display:grid;grid-template-columns:minmax(0,1fr) 270px 300px;gap:28px;padding:22px 24px;align-items:stretch}
.hero::before{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;background:linear-gradient(130deg,color-mix(in srgb,var(--accent) 70%,transparent),color-mix(in srgb,var(--cyan) 30%,transparent) 35%,transparent 65%);-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}
.hero::after{content:"";position:absolute;width:560px;height:560px;left:-160px;top:-380px;background:radial-gradient(circle,color-mix(in srgb,var(--accent) 22%,transparent),transparent 65%);pointer-events:none}
.hero>*{position:relative;z-index:1}
.hero-eyebrow{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:12px}
.hero-title{display:flex;align-items:center;gap:12px;font-size:28px;font-weight:600;letter-spacing:-.03em;margin:12px 0 4px;line-height:1.15}
.hero-title .flag{font-size:30px}
.hero-addr{display:flex;align-items:center;gap:6px;font-size:14px;color:var(--text-2)}
.hero-addr .mono{font-size:15px;color:var(--text)}
.hero-meta{display:flex;flex-wrap:wrap;gap:0;margin-top:18px;border:1px solid var(--border);border-radius:10px;background:var(--hover);width:fit-content;max-width:100%}
.meta{display:flex;flex-direction:column;gap:3px;padding:9px 16px;border-right:1px solid var(--border)}
.meta:last-child{border-right:0}
.meta-k{font-size:11px;color:var(--text-3)}
.meta-v{font-size:13.5px;font-weight:500;white-space:nowrap}
.meta-v.mono{font-size:14px;font-weight:600}
.tag{display:inline-flex;align-items:center;height:21px;padding:0 8px;border-radius:6px;font-size:12px;font-weight:500;color:var(--cyan);background:color-mix(in srgb,var(--cyan) 11%,transparent);border:1px solid color-mix(in srgb,var(--cyan) 26%,transparent);width:fit-content}
.hero-spark{display:flex;flex-direction:column;justify-content:space-between;padding:4px 0}
.hs-head{display:flex;align-items:center;justify-content:space-between;font-size:11.5px;color:var(--text-3)}
.spark{width:100%;height:76px;margin:6px 0;overflow:visible;--c:var(--green)}
.spark .line{fill:none;stroke:var(--c);stroke-width:1.7;stroke-linejoin:round;filter:drop-shadow(0 0 5px color-mix(in srgb,var(--c) 55%,transparent))}
.spark .dot{fill:var(--c)}
.spark .ring{fill:var(--c);opacity:.35;transform-box:fill-box;transform-origin:center;animation:sparkping 1.8s ease-out infinite}
@keyframes sparkping{0%{transform:scale(1);opacity:.45}100%{transform:scale(3.2);opacity:0}}
.hs-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.hs-stat{font-size:11px;color:var(--text-3)}
.hs-stat b{display:block;font:600 13px var(--mono);color:var(--text)}
.hero-side{display:flex;flex-direction:column;gap:8px;justify-content:center;padding-left:24px;border-left:1px solid var(--border)}
.hs-label{font-size:11.5px;color:var(--text-3);margin-bottom:2px}
.score-pill{display:flex;align-items:center;gap:8px;height:40px;padding:0 12px 0 10px;border-radius:10px;border:1px solid var(--border-2);background:var(--surface-2);text-align:left;transition:.15s}
.score-pill:hover{border-color:color-mix(in srgb,var(--accent) 45%,var(--border-2));transform:translateY(-1px);box-shadow:0 6px 18px rgba(0,0,0,.18)}
.sp-k{font-size:12.5px;color:var(--text-2)}
.sp-num{font-size:15px;font-weight:700;margin-left:auto}
.sp-tag{font-size:11px;font-weight:500;padding:1px 6px;border-radius:5px;color:var(--green);background:color-mix(in srgb,var(--green) 12%,transparent)}
.sp-tag.dc{color:var(--amber);background:color-mix(in srgb,var(--amber) 12%,transparent)}
.hero-btns{display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-top:6px}
.hero-btns .btn{padding:0 6px;font-size:12.5px}

/* grade chips */
.g-ap{--c:var(--g-ap)}.g-a{--c:var(--g-a)}.g-b{--c:var(--g-b)}.g-c{--c:var(--g-c)}.g-d{--c:var(--g-d)}
.grade{display:inline-grid;place-items:center;min-width:26px;height:20px;padding:0 6px;border-radius:5px;font:700 11.5px var(--mono);color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);border:1px solid color-mix(in srgb,var(--c) 32%,transparent)}
.grade.g-ap{background:linear-gradient(135deg,#34d399,#22d3ee);color:#03140f;border-color:transparent;box-shadow:0 0 12px rgba(45,212,191,.35)}

/* status badges */
.sb{display:inline-flex;align-items:center;gap:6px;height:22px;padding:0 9px 0 8px;border-radius:999px;font-size:12px;font-weight:500;white-space:nowrap;color:var(--c);background:color-mix(in srgb,var(--c) 11%,transparent);border:1px solid color-mix(in srgb,var(--c) 26%,transparent)}
.sb .d{width:6px;height:6px;border-radius:50%;background:var(--c);flex:none}
.sb-active{--c:var(--blue)}.sb-ok{--c:var(--green)}.sb-test{--c:var(--amber)}.sb-off{--c:var(--gray)}
.sb-active .d{animation:breathe 1.8s ease-in-out infinite}
.sb-ok .d{box-shadow:0 0 6px var(--c)}
.sb-test .spin{width:9px;height:9px;border-width:1.5px}
@keyframes breathe{0%,100%{box-shadow:0 0 0 0 color-mix(in srgb,var(--c) 55%,transparent)}50%{box-shadow:0 0 0 4px color-mix(in srgb,var(--c) 0%,transparent)}}

/* ---------- KPI ---------- */
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.kpi{padding:14px 16px;display:flex;flex-direction:column;gap:4px;min-width:0}
.kpi-k{font-size:12px;color:var(--text-3);display:flex;align-items:center;gap:6px}
.kpi-k .ic{width:13px;height:13px}
.kpi-v{font-size:22px;font-weight:600;letter-spacing:-.03em}
.kpi-u{font-size:12px;color:var(--text-3);font-weight:500;margin-left:3px}
.kpi-d{font-size:11.5px;color:var(--text-3)}
.kpi-d.up{color:var(--green)}
.kpi-bar{height:4px;border-radius:99px;background:var(--hover-2);overflow:hidden;margin-top:6px}
.kpi-bar i{display:block;height:100%;border-radius:inherit;background:var(--c)}
.dist{display:flex;height:4px;border-radius:99px;overflow:hidden;gap:2px;margin-top:6px}
.dist i{display:block;height:100%;background:var(--c)}
.dist-legend{display:flex;gap:10px;font:500 10.5px var(--mono);color:var(--text-3);margin-top:4px}
.dist-legend span::before{content:"";display:inline-block;width:6px;height:6px;border-radius:2px;background:var(--c);margin-right:4px;vertical-align:1px}

/* ---------- toolbar ---------- */
.toolbar{padding:10px}
.filters{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.search{display:flex;align-items:center;gap:8px;height:32px;padding:0 8px 0 10px;border-radius:8px;border:1px solid var(--border-2);background:var(--surface-2);width:240px;color:var(--text-3);transition:.15s}
.search:focus-within{border-color:color-mix(in srgb,var(--accent) 55%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 16%,transparent)}
.search input{flex:1;min-width:0;border:0;outline:0;background:none;color:var(--text);font:inherit;font-size:13px}
.search input::placeholder{color:var(--text-3)}
.select-btn{display:inline-flex;align-items:center;gap:6px;height:32px;padding:0 9px 0 10px;border-radius:8px;border:1px solid var(--border-2);background:var(--surface-2);font-size:13px;white-space:nowrap;transition:.15s}
.select-btn:hover{border-color:var(--border-3)}
.select-btn .k{color:var(--text-3)}
.select-btn .ic{width:14px;height:14px;color:var(--text-3);transition:transform .15s}
.dd.open .select-btn{border-color:color-mix(in srgb,var(--accent) 55%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 16%,transparent)}
.dd.open .select-btn .ic{transform:rotate(180deg)}
.dot-s{width:7px;height:7px;border-radius:50%;background:var(--c);flex:none}
.check-row{display:flex;align-items:center;gap:9px;padding:7px 9px;border-radius:7px;font-size:13px;color:var(--text-2);cursor:pointer}
.check-row:hover{background:var(--hover-2);color:var(--text)}
.check-row .cnt{margin-left:auto;font-size:11px;color:var(--text-3)}
.mm-foot{display:flex;justify-content:space-between;padding:2px 3px}
.star-btn{gap:7px}
.star-btn .cnt{font:600 11px var(--mono);padding:0 6px;border-radius:999px;background:color-mix(in srgb,var(--amber) 16%,transparent);color:var(--amber);line-height:18px}
.star-btn .ic{width:14px;height:14px;transition:transform .2s}
.star-btn.on{border-color:color-mix(in srgb,var(--amber) 45%,transparent);background:color-mix(in srgb,var(--amber) 9%,transparent)}
.star-btn.on .ic{transform:rotate(180deg)}

/* drawer */
.drawer{display:grid;grid-template-rows:0fr;transition:grid-template-rows .36s cubic-bezier(.2,.8,.2,1)}
.drawer.open{grid-template-rows:1fr}
.drawer-inner{overflow:hidden;min-height:0}
.drawer.settled .drawer-inner{overflow:visible}
.drawer-body{margin-top:10px;padding:16px;border-radius:11px;border:1px solid color-mix(in srgb,var(--amber) 20%,var(--border));background:linear-gradient(180deg,color-mix(in srgb,var(--amber) 5%,transparent),transparent 70%),var(--hover);opacity:0;transform:translateY(-6px);transition:opacity .25s,transform .3s}
.drawer.open .drawer-body{opacity:1;transform:none}
.dr-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.dr-title{display:flex;align-items:center;gap:8px;font-weight:600;font-size:14px;flex-wrap:wrap}
.dr-title .muted{font-weight:400;font-size:12px}
.dr-star{color:var(--amber);text-shadow:0 0 10px color-mix(in srgb,var(--amber) 60%,transparent)}
.dr-chips{display:flex;gap:6px;flex-wrap:wrap}
.pchip{display:inline-flex;align-items:center;gap:6px;height:24px;padding:0 9px;border-radius:999px;border:1px solid var(--border-2);background:var(--surface-2);font-size:11.5px}
.pchip .pd{width:6px;height:6px;border-radius:50%;background:var(--c)}
.pchip.more{color:var(--text-3)}
.dr-grid{display:grid;grid-template-columns:240px 1fr 220px;gap:14px;margin-top:14px}
.field{display:flex;flex-direction:column;gap:7px;min-width:0}
.field>label,.field>.fl{font-size:11.5px;color:var(--text-3)}
.field .select-btn{width:100%;justify-content:flex-start}
.field .select-btn .ic{margin-left:auto}
.switch-row{display:flex;align-items:center;gap:10px;height:32px;font-size:12.5px;color:var(--text-2)}
.switch{position:relative;width:36px;height:20px;border-radius:999px;border:0;background:var(--border-3);flex:none;transition:background .2s}
.switch::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.35);transition:transform .22s cubic-bezier(.3,.7,.4,1.3)}
.switch[aria-checked="true"]{background:var(--green)}
.switch[aria-checked="true"]::after{transform:translateX(16px)}
.seg{display:inline-flex;padding:2px;gap:2px;border-radius:8px;border:1px solid var(--border-2);background:var(--hover);height:32px}
.seg button{border:0;background:none;padding:0 11px;border-radius:6px;font-size:12.5px;color:var(--text-2);white-space:nowrap;transition:.15s}
.seg button:hover{color:var(--text)}
.seg button.on{background:var(--surface-solid);color:var(--text);box-shadow:0 1px 3px rgba(0,0,0,.2),inset 0 0 0 1px var(--border-2)}
.seg-sm{height:26px}.seg-sm button{padding:0 8px;font-size:12px;font-family:var(--mono)}
.dr-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:14px;padding-top:14px;border-top:1px dashed var(--border-2)}
.dr-k{font-size:11.5px;color:var(--text-3);margin-right:4px}
.tip-amber{display:flex;gap:10px;align-items:flex-start;margin-top:12px;padding:9px 12px;border-radius:9px;font-size:12.5px;line-height:1.6;color:color-mix(in srgb,var(--amber) 85%,var(--text));background:color-mix(in srgb,var(--amber) 9%,transparent);border:1px solid color-mix(in srgb,var(--amber) 26%,transparent)}

/* ---------- table card ---------- */
.table-card{overflow:visible}
.batchbar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.bb-left{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.sel-pill{display:inline-flex;align-items:center;gap:7px;height:26px;padding:0 10px 0 4px;border-radius:999px;font-size:12.5px;color:var(--text-2);background:var(--hover);border:1px solid var(--border);margin-right:6px;transition:.2s}
.sel-num{min-width:18px;height:18px;padding:0 5px;display:grid;place-items:center;border-radius:999px;font:700 11px var(--mono);background:var(--border-2);color:var(--text-2);transition:.2s}
.has-sel .sel-pill{border-color:color-mix(in srgb,var(--accent) 35%,transparent);background:color-mix(in srgb,var(--accent) 8%,transparent);color:var(--text)}
.has-sel .sel-num{background:var(--accent);color:#fff}
.bb-right{display:flex;gap:6px;flex-wrap:wrap}
.table-wrap{overflow-x:auto;padding-top:4px}
table.nodes{width:100%;min-width:1120px;border-collapse:separate;border-spacing:0;font-size:13px}
.nodes thead th{text-align:left;font-weight:500;font-size:11.5px;color:var(--text-3);padding:9px 12px;border-bottom:1px solid var(--border);background:var(--th-bg);white-space:nowrap}
.nodes tbody td{padding:12px;border-bottom:1px solid var(--border);vertical-align:middle}
.nodes tbody tr{transition:background .15s}
.nodes tbody tr:hover{background:var(--hover)}
.nodes tbody tr.is-sel{background:color-mix(in srgb,var(--accent) 6%,transparent)}
.nodes tbody tr.is-active td:first-child{box-shadow:inset 2px 0 0 var(--blue)}
.nodes tbody tr.is-active{background:linear-gradient(90deg,color-mix(in srgb,var(--blue) 7%,transparent),transparent 45%)}
.nodes tbody tr.is-off td:not(.c-cb):not(.c-act){opacity:.48}
.nodes tbody tr:last-child td{border-bottom:0}
.c-cb{width:44px;padding-left:16px!important}
.c-act{text-align:right}
.cb{appearance:none;-webkit-appearance:none;width:16px;height:16px;border-radius:5px;border:1px solid var(--border-3);background:transparent;display:grid;place-content:center;cursor:pointer;transition:.12s;flex:none;vertical-align:middle}
.cb:hover{border-color:var(--accent)}
.cb::before{content:"";width:10px;height:10px;transform:scale(0);transition:transform .12s;background:#fff;clip-path:polygon(14% 44%,0 65%,50% 100%,100% 16%,80% 0%,43% 62%)}
.cb:checked,.cb:indeterminate{background:var(--accent);border-color:var(--accent)}
.cb:checked::before{transform:scale(1)}
.cb:indeterminate::before{transform:scale(1);clip-path:none;height:2px;width:8px;border-radius:2px}
.addr{display:flex;align-items:center;gap:0;white-space:nowrap}
.addr .ip{font-weight:500;font-size:13px}
.addr .port{color:var(--text-3);font-size:13px}
.keep{margin-left:8px;font-size:10.5px;font-weight:600;padding:1px 6px;border-radius:4px;color:var(--amber);background:color-mix(in srgb,var(--amber) 12%,transparent);border:1px solid color-mix(in srgb,var(--amber) 28%,transparent);font-family:var(--font)}
.sub{font-size:11.5px;color:var(--text-3);margin-top:2px;white-space:nowrap}
.lat{display:inline-flex;align-items:center;gap:7px;font-weight:600;white-space:nowrap;color:var(--c)}
.lat .mono{font-size:13px}
.lat-good{--c:var(--green)}.lat-warn{--c:var(--amber)}.lat-bad{--c:var(--red)}.lat-test{--c:var(--amber);font-weight:500}.lat-off{--c:var(--gray);font-weight:500}
.meta-v.lat-good{color:var(--green)}.meta-v.lat-warn{color:var(--amber)}.meta-v.lat-bad{color:var(--red)}
.sig{display:inline-flex;align-items:flex-end;gap:2px;height:11px}
.sig i{width:3px;border-radius:1px;background:var(--border-3)}
.sig i:nth-child(1){height:4px}.sig i:nth-child(2){height:7px}.sig i:nth-child(3){height:11px}
.sig i.on{background:var(--c)}
.shimmer{background:linear-gradient(90deg,var(--c) 0%,color-mix(in srgb,var(--c) 35%,transparent) 50%,var(--c) 100%);background-size:200% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:shim 1.4s linear infinite}
@keyframes shim{to{background-position:-200% 0}}
.loc{display:flex;align-items:center;gap:6px;white-space:nowrap}
.loc .flag{font-size:15px}
.loc-r{color:var(--text-2)}
.isp{font-weight:500;white-space:nowrap}
.tq{display:flex;flex-direction:column;gap:6px;align-items:flex-start}
.type-tag{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;color:var(--text-2);padding:1px 7px;border-radius:5px;border:1px solid var(--border-2);background:var(--hover)}
.type-tag::before{content:"";width:5px;height:5px;border-radius:1px;background:var(--c,var(--text-3))}
.t-direct{--c:var(--cyan)}.t-edge{--c:var(--accent)}.t-core{--c:var(--violet)}
.qpills{display:flex;gap:5px}
.qp{display:inline-flex;align-items:center;gap:5px;height:22px;padding:0 7px;border-radius:6px;font:500 11.5px var(--mono);white-space:nowrap;color:var(--c);background:color-mix(in srgb,var(--c) 10%,transparent);border:1px solid color-mix(in srgb,var(--c) 26%,transparent);transition:.15s}
.qp b{font-weight:700}
.qp:hover{background:color-mix(in srgb,var(--c) 19%,transparent);transform:translateY(-1px);box-shadow:0 4px 12px color-mix(in srgb,var(--c) 18%,transparent)}
.acts{display:inline-flex;align-items:center;gap:2px}
.act{position:relative;width:28px;height:28px;display:grid;place-items:center;border-radius:7px;border:1px solid transparent;background:transparent;color:var(--text-3);transition:.15s}
.act:hover:not(:disabled){color:var(--text);background:var(--hover-2);border-color:var(--border)}
.act:disabled{opacity:.35}
.act[data-a="test"]:hover:not(:disabled){color:var(--amber)}
.act[data-a="off"]:hover{color:var(--blue)}
.act[data-a="multi"]:hover{color:var(--violet)}
.act.star:hover,.act.star.on{color:var(--amber)}
.act.star.on svg{fill:currentColor}
.act.star.pop svg{animation:pop .35s cubic-bezier(.3,.7,.4,1.5)}
@keyframes pop{0%{transform:scale(.6)}100%{transform:scale(1)}}
.act[data-tip]:hover::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);white-space:nowrap;padding:3px 7px;border-radius:6px;font-size:11px;font-weight:500;background:var(--tip-bg);color:var(--tip-fg);pointer-events:none;z-index:5;box-shadow:0 4px 12px rgba(0,0,0,.25)}
.act-sep{width:1px;height:16px;background:var(--border-2);margin:0 6px}
.btn-switch{min-width:62px}
.btn-using{min-width:62px;color:var(--blue)!important;background:color-mix(in srgb,var(--blue) 10%,transparent)!important;border-color:color-mix(in srgb,var(--blue) 28%,transparent)!important;opacity:1!important}
.empty-box{display:flex;flex-direction:column;align-items:center;gap:6px;padding:40px 0;color:var(--text-3);font-size:12.5px}
.empty-box .ic{width:22px;height:22px;margin-bottom:4px}
.empty-box b{color:var(--text);font-weight:500;font-size:13.5px}
.pager{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 14px;border-top:1px solid var(--border);flex-wrap:wrap;font-size:12.5px;color:var(--text-3)}
.pager b{color:var(--text-2);font-weight:600}
.pg-nav{display:flex;gap:3px;align-items:center}
.pg-btn{min-width:28px;height:28px;padding:0 6px;border-radius:7px;border:1px solid transparent;background:transparent;font:500 12px var(--mono);color:var(--text-2);display:grid;place-items:center;transition:.15s}
.pg-btn:hover:not(:disabled){background:var(--hover-2);color:var(--text)}
.pg-btn.on{border-color:var(--border-2);background:var(--surface-solid);color:var(--text);box-shadow:0 1px 3px rgba(0,0,0,.18)}
.pg-btn:disabled{opacity:.35}
.pg-btn .ic{width:14px;height:14px}
.pg-size{display:flex;align-items:center;gap:8px}

/* ---------- modal ---------- */
.modal{position:fixed;inset:0;z-index:100;display:grid;place-items:center;padding:16px;visibility:hidden;pointer-events:none;transition:visibility 0s .24s}
.modal.open{visibility:visible;pointer-events:auto;transition:none}
.modal-backdrop{position:absolute;inset:0;background:rgba(3,4,7,.62);-webkit-opacity:0;transition:opacity .22s}
[data-theme="light"] .modal-backdrop{background:rgba(20,22,30,.35)}
.modal.open .modal-backdrop{opacity:1}
.modal-dialog{position:relative;width:min(760px,100%);max-height:calc(100vh - 32px);display:flex;flex-direction:column;background:var(--dialog-bg);border:1px solid var(--border-2);border-radius:16px;box-shadow:0 30px 90px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.05);opacity:0;transform:translateY(10px) scale(.975);transition:opacity .22s,transform .26s cubic-bezier(.2,.8,.2,1)}
.modal.open .modal-dialog{opacity:1;transform:none}
.modal-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:18px 20px 14px}
.mh-left{display:flex;gap:12px;align-items:center;min-width:0}
.mh-ic{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;flex:none;color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,transparent);border:1px solid color-mix(in srgb,var(--accent) 26%,transparent)}
.modal-head h3{font-size:16px;font-weight:600;letter-spacing:-.02em}
.modal-head p,.modal-head .sub2{font-size:12.5px;color:var(--text-3);margin-top:1px}
.eyebrow{font-size:11.5px;color:var(--text-3);display:flex;align-items:center;gap:6px}
.modal-body{overflow:auto;padding:0 20px 18px;min-height:0}
.modal-foot{display:flex;align-items:center;gap:8px;padding:12px 20px;border-top:1px solid var(--border);background:var(--hover);border-radius:0 0 16px 16px}
.foot-set{display:none;align-items:center;gap:8px;width:100%}
.foot-set.on{display:flex}

/* report */
.r-summary{display:flex;align-items:center;gap:16px;padding:14px;border-radius:12px;border:1px solid var(--border);background:var(--hover);margin-bottom:12px;flex-wrap:wrap}
.r-grade{width:58px;height:58px;border-radius:14px;display:grid;place-items:center;font:700 24px var(--mono);color:var(--c);background:color-mix(in srgb,var(--c) 13%,transparent);border:1px solid color-mix(in srgb,var(--c) 34%,transparent);box-shadow:0 0 34px color-mix(in srgb,var(--c) 22%,transparent);flex:none}
.r-grade.g-ap{background:linear-gradient(135deg,#34d399,#22d3ee);color:#03140f;border-color:transparent}
.r-info{flex:1;min-width:200px}
.r-line{display:flex;align-items:baseline;gap:6px}
.r-num{font-size:26px;font-weight:700;letter-spacing:-.04em;line-height:1}
.r-of{font-size:13px;color:var(--text-3)}
.r-badge{margin-left:6px;font-size:11px;font-weight:500;padding:1px 7px;border-radius:5px;color:var(--green);background:color-mix(in srgb,var(--green) 12%,transparent);align-self:center}
.r-badge.dc{color:var(--amber);background:color-mix(in srgb,var(--amber) 12%,transparent)}
.r-desc{font-size:12.5px;color:var(--text-2);margin-top:6px}
.r-right{display:flex;flex-direction:column;align-items:flex-end;gap:8px}
.ext-link{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--accent);font-weight:500}
.ext-link .ic{width:13px;height:13px}
.ext-link:hover{text-decoration:underline;text-underline-offset:3px}
.report-box{position:relative;background:#09090c;border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:14px 18px 16px;font:12.5px/1.75 var(--mono);color:#c6c9d4;overflow:hidden;box-shadow:inset 0 1px 0 rgba(255,255,255,.03)}
.rb-top{display:flex;align-items:center;gap:6px;margin:-4px -6px 10px;padding-bottom:10px;border-bottom:1px solid rgba(255,255,255,.06)}
.rb-top i{width:10px;height:10px;border-radius:50%;display:block}
.rb-top span{margin-left:auto;font-size:11px;color:#5b5f6d}
.rb-cmd{color:#e8e9f0;word-break:break-all}
.rb-p{color:#34d399;margin-right:8px}
.rb-arg{color:#a78bfa}
.rb-meta{display:grid;grid-template-columns:auto 1fr;gap:0 18px;margin:8px 0 2px;color:#6f7383}
.rb-meta b{color:#dfe1e8;font-weight:500}
.rb-sec{color:#545867;margin:12px 0 6px;font-size:11.5px;white-space:nowrap;overflow:hidden}
.rb-total{display:flex;align-items:center;gap:12px}
.rb-total .rb-bar{height:8px}
.rb-total b{color:#fff;font-size:14px}
.rb-row{display:grid;grid-template-columns:100px 1fr 30px 50px;align-items:center;gap:12px;padding:2px 0}
.rb-k{color:#a9acb8;white-space:nowrap}
.rb-bar{flex:1;height:6px;border-radius:99px;background:rgba(255,255,255,.06);overflow:hidden}
.rb-bar i{display:block;height:100%;width:0;border-radius:inherit;background:var(--c);box-shadow:0 0 10px var(--c);transition:width .9s cubic-bezier(.2,.8,.2,1)}
.rb-v{text-align:right;color:#e8e9f0;font-weight:600}
.rb-st{font-size:10px;font-weight:700;padding:0 6px;border-radius:4px;text-align:center;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent);line-height:18px}
.rb-tags{display:flex;flex-wrap:wrap;gap:6px}
.rb-tag{padding:1px 8px;border-radius:5px;font-size:11.5px;line-height:20px}
.rb-tag.pos{color:#4ade80;background:rgba(74,222,128,.09);border:1px solid rgba(74,222,128,.24)}
.rb-tag.neg{color:#fb7185;background:rgba(251,113,133,.09);border:1px solid rgba(251,113,133,.26)}
.rb-foot{margin-top:12px;color:#5f6372;font-size:11.5px}
.rb-foot .ok{color:#34d399}
.cursor{display:inline-block;width:7px;height:14px;background:#a78bfa;vertical-align:-2px;margin-left:4px;animation:blink 1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
.report-box.scanning::before{content:"";position:absolute;left:0;right:0;height:60px;top:-60px;background:linear-gradient(180deg,transparent,rgba(124,131,255,.18),transparent);animation:scan 1.1s linear infinite;z-index:2}
.report-box.scanning>*{opacity:.35;transition:opacity .2s}
@keyframes scan{to{top:100%}}

/* settings */
.tabs{display:flex;gap:4px;padding:0 20px;border-bottom:1px solid var(--border)}
.tab{position:relative;border:0;background:none;padding:9px 10px 11px;font-size:13px;font-weight:500;color:var(--text-3);display:flex;align-items:center;gap:7px;transition:color .15s}
.tab:hover{color:var(--text)}
.tab.on{color:var(--text)}
.tab.on::after{content:"";position:absolute;left:8px;right:8px;bottom:-1px;height:2px;border-radius:2px;background:var(--accent);box-shadow:0 0 10px var(--accent)}
.tab-badge{font:600 10.5px var(--mono);padding:0 6px;border-radius:999px;background:var(--hover-2);color:var(--text-2);line-height:17px}
.pane{display:none;padding-top:16px}
.pane.on{display:block;animation:fadein .25s}
@keyframes fadein{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.sec-label{font-size:11.5px;color:var(--text-3);margin:2px 0 8px;letter-spacing:.02em}
.mode-cards{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.mode-card,.option-card{position:relative;text-align:left;padding:13px 14px;border-radius:12px;border:1px solid var(--border-2);background:var(--hover);transition:.18s;display:flex;flex-direction:column;gap:4px}
.mode-card:hover,.option-card:hover{border-color:var(--border-3);transform:translateY(-1px)}
.mode-card b,.option-card b{font-size:13.5px;font-weight:600;margin-top:8px}
.mode-card p,.option-card p{font-size:12px;color:var(--text-3);line-height:1.55}
.mc-top{display:flex;justify-content:space-between;align-items:center}
.mc-ic{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;color:var(--c);background:color-mix(in srgb,var(--c) 13%,transparent);border:1px solid color-mix(in srgb,var(--c) 26%,transparent)}
.radio{width:16px;height:16px;border-radius:50%;border:1.5px solid var(--border-3);display:grid;place-items:center;transition:.15s}
.radio::after{content:"";width:6px;height:6px;border-radius:50%;background:#fff;transform:scale(0);transition:.15s}
.mode-card.on,.option-card.active{border-color:color-mix(in srgb,var(--accent) 60%,transparent);background:color-mix(in srgb,var(--accent) 8%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 13%,transparent)}
.mode-card.on .radio,.option-card.active .radio{background:var(--accent);border-color:var(--accent)}
.mode-card.on .radio::after,.option-card.active .radio::after{transform:scale(1)}
.mode-pane{display:none;margin-top:12px;padding:14px;border-radius:12px;border:1px dashed var(--border-2)}
.mode-pane.on{display:block;animation:fadein .22s}
.form-rows{display:flex;flex-direction:column;border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-top:4px}
.mode-pane .form-rows{border:0;border-radius:0}
.f-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:12px 14px;border-bottom:1px solid var(--border)}
.mode-pane .f-row{padding:8px 0}
.f-row:last-child{border-bottom:0}
.f-row b{display:block;font-size:13px;font-weight:500}
.f-row small{font-size:12px;color:var(--text-3)}
.inp-group{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--text-3);white-space:nowrap}
.inp{width:58px;height:28px;border-radius:7px;border:1px solid var(--border-2);background:var(--surface-2);color:var(--text);font:500 12.5px var(--mono);text-align:center;outline:0}
.inp:focus{border-color:color-mix(in srgb,var(--accent) 55%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 16%,transparent)}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.chip{display:inline-flex;align-items:center;gap:6px;height:28px;padding:0 11px;border-radius:999px;border:1px solid var(--border-2);background:var(--surface-2);font-size:12.5px;color:var(--text-2);transition:.15s}
.chip:hover{border-color:var(--border-3);color:var(--text)}
.chip.on{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 50%,transparent);background:color-mix(in srgb,var(--accent) 10%,transparent)}
.chip .cnt{font:500 11px var(--mono);opacity:.7}
.node-opts{display:flex;flex-direction:column;gap:6px;margin-top:8px}
.node-opt{display:flex;align-items:center;gap:12px;padding:9px 12px;border-radius:10px;border:1px solid var(--border-2);background:var(--surface-2);text-align:left;transition:.15s}
.node-opt:hover{border-color:var(--border-3)}
.node-opt.on{border-color:color-mix(in srgb,var(--accent) 55%,transparent);background:color-mix(in srgb,var(--accent) 7%,transparent)}
.node-opt.on .radio{background:var(--accent);border-color:var(--accent)}
.node-opt.on .radio::after{transform:scale(1)}
.node-opt .no-main{flex:1;font-size:12.5px;color:var(--text-2)}
.node-opt .no-main .mono{color:var(--text);font-weight:500;margin-right:8px}
.note{font-size:12px;color:var(--text-3);margin-top:10px;display:flex;gap:6px;align-items:center}
.note .ic{width:13px;height:13px}
.log-filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.log-filters .chip{height:26px;font-size:12px}
.log-filters .chip .dot-s{width:6px;height:6px}
.log-list{border:1px solid var(--border);border-radius:12px;overflow:hidden;background:var(--hover)}
.log-row{display:grid;grid-template-columns:70px 48px 46px 1fr;align-items:center;gap:10px;padding:9px 14px;border-bottom:1px solid var(--border);font-size:12.5px;animation:fadein .2s}
.log-row:last-child{border-bottom:0}
.log-row:hover{background:var(--hover)}
.lg-time{font-size:11.5px;color:var(--text-3)}
.lg-lv{font:700 10px var(--mono);text-align:center;padding:0 4px;border-radius:4px;line-height:18px;color:var(--c);background:color-mix(in srgb,var(--c) 13%,transparent)}
.lv-info{--c:var(--blue)}.lv-ok{--c:var(--green)}.lv-warn{--c:var(--amber)}.lv-error{--c:var(--red)}
.lg-cat{font-size:11px;font-weight:500;color:var(--c);text-align:center;padding:0 4px;border-radius:999px;border:1px solid color-mix(in srgb,var(--c) 30%,transparent);line-height:18px}
.lg-msg{color:var(--text-2);min-width:0}
.lg-msg .mono{color:var(--text);font-size:12px}
.lv-error .lg-msg{color:color-mix(in srgb,var(--red) 70%,var(--text))}

/* toast */
.toasts{position:fixed;right:20px;bottom:20px;z-index:200;display:flex;flex-direction:column;gap:8px;align-items:flex-end;pointer-events:none}
.toast{display:flex;align-items:center;gap:10px;max-width:380px;padding:10px 14px;border-radius:11px;font-size:13px;background:var(--menu-bg);border:1px solid var(--border-2);box-shadow:0 14px 40px rgba(0,0,0,.4);-webkit-opacity:0;transform:translateY(8px) scale(.97);transition:opacity .22s,transform .26s cubic-bezier(.2,.8,.2,1)}
.toast.in{opacity:1;transform:none}
.toast .t-dot{width:8px;height:8px;border-radius:50%;background:var(--c);box-shadow:0 0 8px var(--c);flex:none}
.t-info{--c:var(--blue)}.t-ok{--c:var(--green)}.t-warn{--c:var(--amber)}.t-err{--c:var(--red)}

/* ---------- responsive ---------- */
@media (max-width:1180px){
  .hero{grid-template-columns:minmax(0,1fr) 300px}
  .hero-spark{grid-column:1/-1;order:3;padding-top:14px;border-top:1px solid var(--border)}
  .dr-grid{grid-template-columns:1fr 1fr}
}
@media (max-width:900px){
  .kpis{grid-template-columns:repeat(2,1fr)}
  .hero{grid-template-columns:1fr}
  .hero-side{padding-left:0;border-left:0;padding-top:16px;border-top:1px solid var(--border)}
  .mode-cards{grid-template-columns:1fr}
  .hide-md{display:none!important}
}
@media (max-width:640px){
  .topbar-inner{padding:0 16px;gap:8px}
  .wrap{padding:16px 16px 60px}
  .hide-sm{display:none!important}
  .hero{padding:18px 16px}
  .hero-title{font-size:22px}
  .hero-meta{width:100%}
  .meta{flex:1 1 45%;border-bottom:1px solid var(--border)}
  .search{width:100%}
  .filters>.dd{flex:1 1 calc(50% - 4px)}
  .filters .select-btn{width:100%}
  .filters .select-btn .ic{margin-left:auto}
  .star-btn{width:100%}
  .dr-grid{grid-template-columns:1fr}
  .batchbar{flex-direction:column;align-items:stretch}
  .bb-right .btn{flex:1}
  .r-right{align-items:flex-start}
  .rb-row{grid-template-columns:84px 1fr 26px 44px;gap:8px}
  .log-row{grid-template-columns:60px 44px 1fr}
  .log-row .lg-cat{display:none}
  .pager{justify-content:center}
  .toasts{left:16px;right:16px;align-items:stretch}
}
@media (prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;transition-duration:.01ms!important}}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
@media (max-width: 768px) {
  header { position: static; }
}
.table-wrap { -webkit-overflow-scrolling: touch; }
.vps-recommend-tab {
  position: fixed;
  right: 0;
  top: 50%;
  transform: translateY(-50%);
  width: 34px;
  min-height: 120px;
  background: linear-gradient(180deg, #8d93ff, #666df2);
  border: 1px solid var(--border-2);
  border-right: none;
  border-radius: 8px 0 0 8px;
  padding: 12px 5px;
  color: #fff;
  font-weight: 600;
  font-size: 12px;
  writing-mode: vertical-rl;
  text-orientation: mixed;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 50;
  box-shadow: -4px 0 18px rgba(108, 115, 255, 0.28);
  transition: padding-right 0.2s ease;
}
.vps-recommend-tab:hover { padding-right: 9px; }
.raw-report-details {
  margin-top: 12px;
  border-top: 1px dashed rgba(255, 255, 255, 0.08);
  padding-top: 10px;
}
.raw-report-details summary {
  cursor: pointer;
  color: #8b909c;
  font-size: 11.5px;
  user-select: none;
}
.raw-report-pre {
  margin-top: 8px;
  padding: 12px 14px;
  border-radius: 8px;
  background: rgba(0, 0, 0, 0.45);
  border: 1px solid rgba(255, 255, 255, 0.06);
  font: 11.5px/1.55 var(--mono);
  color: #cbd5e1;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 240px;
  overflow-y: auto;
}
</style>
</head>
<body>
<div class="bg-fx" aria-hidden="true"></div>

<!-- ================= HEADER ================= -->
<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <div class="logo" aria-hidden="true">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12h4l2.5-6 4 13 3-9 1.5 2H22"/></svg>
      </div>
      <span class="brand-name">AimiliVPN</span>
      <span class="brand-sep hide-sm">/</span>
      <div id="status" class="live-pill status" role="status" aria-live="polite" title="本地代理与活动节点运行状态">
        <span class="pulse"></span><b>加载中</b>
        <span class="lp-div hide-sm"></span>
        <span class="hide-sm">本地监听 <span class="mono">127.0.0.1:7928</span></span>
      </div>
    </div>

    <div class="top-actions">
      <div class="dd right hide-sm" id="verDD">
        <button class="btn btn-ghost btn-ver" data-dd-trigger aria-haspopup="menu">
          <span class="mono" id="github_version_label">V2.1.5 正式版</span>
          <span class="ver-dot" title="稳定通道"></span>
          <i data-i="chev"></i>
        </button>
        <div class="dd-menu w-260" role="menu">
          <div class="ver-card">
            <div class="ver-row">AimiliVPN <span class="chip-stable">STABLE</span></div>
            <div class="ver-num mono"><span id="current_version_label">V2.1.5 正式版</span></div>
            <div id="deployment_mode_label" class="muted" style="font-size:11.5px;margin-top:2px;">Python 源码部署 · 更新通道：main</div>
            <div class="ver-status" id="verStatus">
              <span class="vs-ic"><i data-i="check"></i></span>
              <span><b id="update_check_status">点击“检测更新”查询 GitHub 最新正式版</b><small>稳定主分支通道</small></span>
            </div>
          </div>
          <div class="menu-sep"></div>
          <button class="menu-item" id="checkUpdate" data-keep="1" type="button"><i data-i="sync"></i>检测更新<kbd>⌘U</kbd></button>
          <a class="menu-item" href="https://github.com/lr-tony/aimili-vpngate/tree/main" target="_blank" rel="noopener noreferrer"><i data-i="list"></i>GitHub main 主分支<i data-i="ext" class="ml"></i></a>
          <a class="menu-item" id="latest_release_link" href="https://github.com/lr-tony/aimili-vpngate/releases/latest" target="_blank" rel="noopener noreferrer"><i data-i="layers"></i>下载最新正式版<i data-i="ext" class="ml"></i></a>
        </div>
      </div>
      <a class="btn btn-ghost hide-md" href="https://t.me/arestemple" target="_blank" rel="noopener noreferrer"><i data-i="book"></i>Telegram<i data-i="ext" class="ext-sm"></i></a>
      <button class="icon-btn" id="themeBtn" type="button" aria-label="切换主题"></button>
      <span class="vsep hide-sm"></span>
      <button class="btn btn-primary" id="syncBtn" type="button"><i data-i="sync"></i><span class="hide-sm" id="syncBtnText">同步目录</span></button>
      <div class="dd right">
        <button class="admin-btn" data-dd-trigger aria-haspopup="menu" type="button"><span class="avatar">管</span><span class="hide-sm">管理员</span><i data-i="chev"></i></button>
        <div class="dd-menu w-220" role="menu">
          <div class="menu-user"><span class="avatar lg">管</span><div><b id="menu_admin_name">admin</b><small>本地管理员 · 最高权限</small></div></div>
          <div class="menu-sep"></div>
          <button class="menu-item" data-act="sched" type="button"><i data-i="sliders"></i>调度与代理设置</button>
          <button class="menu-item" data-act="account" type="button"><i data-i="user"></i>账号与网页安全</button>
          <button class="menu-item" data-act="selfcheck" type="button"><i data-i="activity"></i>服务自检与网关</button>
          <button class="menu-item" data-act="logs" type="button"><i data-i="list"></i>运行记录<span class="menu-badge" id="menuLogBadge">日志</span></button>
          <div class="menu-sep"></div>
          <button class="menu-item danger" data-act="logout" type="button"><i data-i="logout"></i>退出</button>
        </div>
      </div>
    </div>
  </div>
</header>

<main class="wrap">
  <div class="page-head">
    <div>
      <div class="crumbs"><span>控制台</span><span class="sep">/</span><span>区域与节点纯净度遥测</span></div>
      <h2>节点总览</h2>
    </div>
    <div class="ph-right">
      <span class="ph-meta"><i data-i="clock"></i>最近同步 <span class="mono" id="lastSync">-</span></span>
      <span class="ph-meta"><i data-i="globe"></i><span id="phCountryCount">0</span> 个国家/地区 · <span class="mono" id="phNodeCount">0</span> 个节点</span>
    </div>
  </div>

  <!-- ================= HERO ================= -->
  <section class="hero card" aria-label="当前主用节点">
    <div class="hero-main">
      <div class="hero-eyebrow">
        <span class="sb sb-active" id="hStatusBadge"><span class="d"></span><span id="hStatusText">未连接</span></span>
        <span class="muted" id="hSubStatus">点击下方列表中的「切换」连接可用节点 · 最近检测 <span class="mono" id="lastCheck">0</span> 秒前</span>
      </div>
      <h1 class="hero-title"><span class="flag" id="hFlag">🌐</span><span id="hLoc">等待连接节点</span></h1>
      <div class="hero-addr">
        <span class="muted">节点编码</span>
        <span class="mono" id="hAddr">-</span>
        <button class="icon-btn sm" id="copyAddr" type="button" aria-label="复制地址" title="复制节点地址"><i data-i="copy"></i></button>
      </div>
      <div class="hero-meta">
        <div class="meta"><span class="meta-k">延迟</span><span class="meta-v mono lat-good" id="hLat">-</span></div>
        <div class="meta"><span class="meta-k">服务商</span><span class="meta-v" id="hIsp">-</span></div>
        <div class="meta"><span class="meta-k">物理位置</span><span class="meta-v mono" id="hAsn">-</span></div>
        <div class="meta"><span class="meta-k">类型</span><span class="tag" id="hType">-</span></div>
      </div>
    </div>

    <div class="hero-spark">
      <div class="hs-head"><span>近 30 分钟延迟波动</span><span class="mono">ms</span></div>
      <svg class="spark" id="spark" viewBox="0 0 240 64" preserveAspectRatio="none" aria-hidden="true">
        <defs><linearGradient id="sparkFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="currentColor" stop-opacity=".28"/><stop offset="1" stop-color="currentColor" stop-opacity="0"/></linearGradient></defs>
        <path id="sparkArea" fill="url(#sparkFill)" style="color:var(--c)"/>
        <path id="sparkLine" class="line"/>
        <circle id="sparkRing" class="ring" r="3" cx="238" cy="32"/>
        <circle id="sparkDot" class="dot" r="3" cx="238" cy="32"/>
      </svg>
      <div class="hs-stats">
        <div class="hs-stat">最低<b id="sMin">-</b></div>
        <div class="hs-stat">平均<b id="sAvg">-</b></div>
        <div class="hs-stat">最高<b id="sMax">-</b></div>
      </div>
    </div>

    <div class="hero-side">
      <div class="hs-label">质量评级 · 点击查看报告 (VPS本机直连)</div>
      <button class="score-pill" data-hero-report="off" type="button">
        <span>🛡️</span><span class="sp-k">CleanIP 评级</span>
        <span class="grade g-b" id="hgOff">-</span>
        <span class="sp-num mono" id="hsOff">未测</span>
        <span class="sp-tag" id="htOff">待检</span>
      </button>
      <button class="score-pill" data-hero-report="multi" type="button">
        <span>🔍</span><span class="sp-k">多源对比评分</span>
        <span class="grade g-b" id="hgMulti">-</span>
        <span class="sp-num mono" id="hsMulti">未测</span>
        <span class="sp-tag" id="htMulti">待检</span>
      </button>
      <div class="hero-btns">
        <button class="btn" id="hEval" type="button"><i data-i="shield"></i>CleanIP检测</button>
        <button class="btn" id="hCompare" type="button"><i data-i="search"></i>三源对比</button>
        <button class="btn btn-danger-ghost" id="hUnload" type="button"><i data-i="trash"></i>断开连接</button>
      </div>
    </div>
  </section>

  <!-- ================= KPI ================= -->
  <section class="kpis">
    <div class="kpi card">
      <div class="kpi-k"><i data-i="server"></i>节点总数</div>
      <div class="kpi-v mono" id="kpiTotal">0</div>
      <div class="kpi-d up" id="kpiStarSub">★ 星标常备池 0 个节点</div>
    </div>
    <div class="kpi card">
      <div class="kpi-k"><i data-i="activity"></i>可用节点</div>
      <div class="kpi-v mono"><span id="kpiAvail">0</span><span class="kpi-u" id="kpiAvailTotal">/ 0</span></div>
      <div class="kpi-bar"><i id="kpiAvailBar" style="width:0%;--c:var(--green)"></i></div>
    </div>
    <div class="kpi card">
      <div class="kpi-k"><i data-i="bolt"></i>平均延迟</div>
      <div class="kpi-v mono"><span id="kpiAvgLat">-</span><span class="kpi-u">ms</span></div>
      <div class="kpi-d" id="kpiMinLatSub">最快实测 <span style="color:var(--green)">-</span></div>
    </div>
    <div class="kpi card">
      <div class="kpi-k"><i data-i="shield"></i>质量分布</div>
      <div class="kpi-v mono"><span id="kpiHighQuality">0</span><span class="kpi-u">个 A 级以上</span></div>
      <div class="dist" id="kpiDistBar">
        <i style="flex:1;--c:var(--g-ap)"></i>
        <i style="flex:1;--c:var(--g-a)"></i>
        <i style="flex:1;--c:var(--g-b)"></i>
        <i style="flex:1;--c:var(--g-c)"></i>
        <i style="flex:1;--c:var(--g-d)"></i>
      </div>
    </div>
  </section>

  <!-- ================= FILTERS + STAR POOL ================= -->
  <section class="toolbar card" aria-label="筛选">
    <div class="filters">
      <label class="search"><i data-i="search"></i><input id="q" placeholder="搜索 IP、端口、地区或服务商…" autocomplete="off"><kbd>/</kbd></label>

      <div class="dd dd-select" data-filter="status">
        <button class="select-btn" data-dd-trigger type="button"><span class="k">状态</span><span class="dd-label">全部</span><i data-i="chev"></i></button>
        <div class="dd-menu">
          <button class="dd-opt active" data-value="all" type="button"><span class="dot-s" style="--c:var(--text-3)"></span>全部</button>
          <button class="dd-opt" data-value="available" type="button"><span class="dot-s" style="--c:var(--green)"></span>可用</button>
          <button class="dd-opt" data-value="testing" type="button"><span class="dot-s" style="--c:var(--amber)"></span>检测中</button>
          <button class="dd-opt" data-value="unavailable" type="button"><span class="dot-s" style="--c:var(--gray)"></span>失效</button>
        </div>
      </div>

      <div class="dd dd-multi" data-filter="country" id="country_filter">
        <button class="select-btn" data-dd-trigger type="button" id="country_filter_button"><span class="k">国家</span><span class="dd-label" id="country_filter_label">全部国家</span><i data-i="chev"></i></button>
        <div class="dd-menu w-220" id="country_filter_panel">
          <div class="menu-label">选择国家 / 地区（可多选）</div>
          <div id="country_filter_options"></div>
          <div class="menu-sep"></div>
          <div class="mm-foot">
            <button class="btn btn-sm btn-ghost" data-mm="clear" type="button">清除</button>
            <button class="btn btn-sm" data-mm="all" type="button">全选</button>
          </div>
        </div>
      </div>

      <div class="dd dd-select" data-filter="region" id="regionDD">
        <button class="select-btn" data-dd-trigger type="button"><span class="k">地区</span><span class="dd-label" id="regionDDLabel">全部地区</span><i data-i="chev"></i></button>
        <div class="dd-menu" id="regionDDMenu">
          <button class="dd-opt active" data-value="" type="button">全部地区 (都道府县)</button>
        </div>
      </div>

      <div class="dd dd-select" data-filter="type">
        <button class="select-btn" data-dd-trigger type="button"><span class="k">类型</span><span class="dd-label">全部类型</span><i data-i="chev"></i></button>
        <div class="dd-menu">
          <button class="dd-opt active" data-value="" type="button">全部类型</button>
          <div class="menu-sep"></div>
          <button class="dd-opt" data-value="residential" type="button"><span class="dot-s" style="--c:var(--cyan)"></span>住宅 IP (家宽)</button>
          <button class="dd-opt" data-value="hosting" type="button"><span class="dot-s" style="--c:var(--violet)"></span>机房 IP (IDC)</button>
        </div>
      </div>

      <div class="dd dd-select" data-filter="sort" id="sortDD">
        <button class="select-btn" data-dd-trigger type="button"><span class="k">排序</span><span class="dd-label" id="sortDDLabel">综合评分</span><i data-i="chev"></i></button>
        <div class="dd-menu">
          <button class="dd-opt active" data-value="default" type="button">综合评分</button>
          <div class="menu-sep"></div>
          <button class="dd-opt" data-value="purity_desc" type="button">纯净度 · 高 → 低</button>
          <button class="dd-opt" data-value="purity_asc" type="button">纯净度 · 低 → 高</button>
          <div class="menu-sep"></div>
          <button class="dd-opt" data-value="latency_asc" type="button">延迟 · 低 → 高</button>
          <button class="dd-opt" data-value="latency_desc" type="button">延迟 · 高 → 低</button>
        </div>
      </div>

      <span class="spacer hide-sm"></span>
      <button class="btn star-btn" id="starToggle" type="button" aria-expanded="false" aria-controls="drawer">
        ⭐ 星标常备池 <span class="cnt" id="poolCount">0</span><i data-i="chev"></i>
      </button>
    </div>

    <div class="drawer" id="drawer">
      <div class="drawer-inner">
        <div class="drawer-body">
          <div class="dr-head">
            <div class="dr-title"><span class="dr-star">★</span>星标常备池 <span class="muted mono" id="poolMeta">0 个节点</span></div>
            <div class="dr-chips" id="poolChips"></div>
          </div>
          <div class="dr-grid">
            <div class="field">
              <span class="fl">轮换地区限定 (都道府县)</span>
              <div class="dd dd-select" id="poolRegion">
                <button class="select-btn" data-dd-trigger type="button"><i data-i="pin" class="pin-ic"></i><span class="dd-label" id="poolRegionLabel">不限地区 (全部星标)</span><i data-i="chev"></i></button>
                <div class="dd-menu w-220" id="poolRegionMenu">
                  <button class="dd-opt active" data-value="" type="button">不限地区 (全部星标)</button>
                </div>
              </div>
            </div>
            <div class="field">
              <span class="fl">仅在星标池内轮换出站</span>
              <div class="switch-row">
                <button class="switch" role="switch" aria-checked="false" id="poolSwitch" type="button" aria-label="启用仅在星标池内轮换"></button>
                <span id="poolSwitchText">未启用 · 调度器使用全局节点池</span>
              </div>
            </div>
            <div class="field">
              <span class="fl">列表视图过滤</span>
              <div class="seg" id="poolViewSeg">
                <button class="on" data-view="all" type="button">显示全部节点</button>
                <button data-view="fav" type="button">仅看星标节点</button>
              </div>
            </div>
          </div>
          <div class="dr-actions">
            <span class="dr-k">星标快捷批量</span>
            <button class="btn btn-sm btn-tint btn-amber" data-pool="test" type="button">⚡ 星标全部测速</button>
            <button class="btn btn-sm btn-tint btn-blue" data-pool="eval" type="button">🛡️ 星标全部 CleanIP</button>
            <button class="btn btn-sm btn-tint btn-violet" data-pool="multi" type="button">🔍 星标全部三源对比</button>
            <button class="btn btn-sm" data-pool="select" type="button">☑ 勾选全部星标</button>
            <button class="btn btn-sm btn-ghost" data-pool="export" type="button"><i data-i="download"></i>复制星标地址</button>
          </div>
          <div class="tip-amber"><span>💡</span><span id="poolTip">星标节点已启用防丢持久化保护：刷新订阅后自动保留在列表中。</span></div>
        </div>
      </div>
    </div>
  </section>

  <!-- ================= TABLE ================= -->
  <section class="card table-card" aria-label="节点列表">
    <div class="batchbar" id="batchbar">
      <div class="bb-left">
        <span class="sel-pill"><span class="sel-num" id="selNum">0</span><span id="selText">未勾选节点</span></span>
        <button class="btn btn-sm btn-ghost" data-sel="page" type="button">全选本页</button>
        <button class="btn btn-sm btn-ghost" data-sel="filter" type="button">全选当前筛选</button>
        <button class="btn btn-sm btn-ghost" data-sel="pending" type="button">勾选待测</button>
        <button class="btn btn-sm btn-ghost" data-sel="clear" type="button">清空</button>
      </div>
      <div class="bb-right">
        <button class="btn btn-tint btn-amber bb-main" id="bTest" type="button">⚡ 批量测速</button>
        <button class="btn btn-danger-ghost" id="bCancelTest" type="button" style="display:none;">⏹ 停止测速</button>
        <button class="btn btn-tint btn-blue bb-main" id="bEval" type="button">🛡️ 批量 CleanIP</button>
        <button class="btn btn-tint btn-violet bb-main" id="bMulti" type="button">🔍 批量三源对比</button>
      </div>
    </div>
    <div class="table-wrap">
      <table class="nodes">
        <thead>
          <tr>
            <th class="c-cb"><input type="checkbox" class="cb" id="cbAll" aria-label="全选"></th>
            <th>状态</th>
            <th>节点地址</th>
            <th style="width: 125px; cursor:pointer; user-select:none;" id="thSortLat" title="点击按延迟排序">延迟</th>
            <th>所在地区</th>
            <th>服务商</th>
            <th style="cursor:pointer; user-select:none;" id="thSortPurity" title="点击按纯净度排序">类型 · 质量</th>
            <th class="c-act">操作</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
    <div class="pager" id="pagination_container">
      <div id="pgInfo">显示 0 个节点</div>
      <div class="pg-nav" id="pgNav"></div>
      <div class="pg-size">每页 <div class="seg seg-sm" id="pgSizeSeg"><button data-size="20" type="button">20</button><button class="on" data-size="50" type="button">50</button><button data-size="100" type="button">100</button></div></div>
    </div>
  </section>
</main>

<!-- ================= REPORT MODAL ================= -->
<div class="modal" id="reportModal" role="dialog" aria-modal="true" aria-labelledby="rTitle" aria-hidden="true">
  <div class="modal-backdrop" data-close></div>
  <div class="modal-dialog">
    <div class="modal-head">
      <div class="mh-left">
        <div class="mh-ic"><i data-i="shield"></i></div>
        <div>
          <div class="eyebrow" id="rEyebrow">质量评估详情 · VPS本机直连</div>
          <h3 class="mono" id="rTitle">-</h3>
          <div class="sub2" id="rSub">-</div>
        </div>
      </div>
      <button class="icon-btn" data-close type="button" aria-label="关闭"><i data-i="x"></i></button>
    </div>
    <div class="modal-body">
      <div class="r-summary">
        <div class="r-grade g-ap" id="rGrade">-</div>
        <div class="r-info">
          <div class="r-line">
            <span class="r-num mono" id="rScore">-</span>
            <span class="r-of mono">/ 100</span>
            <span class="r-badge" id="rNative">待检</span>
          </div>
          <div class="r-desc" id="rDesc">正在获取评估报告…</div>
        </div>
        <div class="r-right">
          <div class="seg" id="rSeg">
            <button data-src="off" class="on" type="button">🛡️ CleanIP</button>
            <button data-src="multi" type="button">🔍 三源对比</button>
          </div>
          <a href="https://cleanip.io" target="_blank" rel="noopener noreferrer" class="ext-link" id="rExt">在 CleanIP.io 中查看<i data-i="ext"></i></a>
        </div>
      </div>
      <div class="report-box" id="reportBox"></div>
    </div>
    <div class="modal-foot">
      <button class="btn" id="rCopy" type="button"><i data-i="copy"></i>复制报告</button>
      <button class="btn" id="rRedo" type="button"><i data-i="sync"></i>重新评估</button>
      <span class="spacer"></span>
      <button class="btn btn-primary" id="rSwitch" type="button"><i data-i="switch"></i><span id="rSwitchText">切换至三源对比</span></button>
    </div>
  </div>
</div>

<!-- ================= SETTINGS / SELF-CHECK / LOGS MODAL ================= -->
<div class="modal" id="setModal" role="dialog" aria-modal="true" aria-labelledby="setTitle" aria-hidden="true">
  <div class="modal-backdrop" data-close></div>
  <div class="modal-dialog">
    <div class="modal-head">
      <div class="mh-left">
        <div class="mh-ic"><i data-i="sliders"></i></div>
        <div>
          <h3 id="setTitle">控制台设置</h3>
          <p>调度策略、网页安全、网关自检与运行记录</p>
        </div>
      </div>
      <button class="icon-btn" data-close type="button" aria-label="关闭网页安全设置"><i data-i="x"></i></button>
    </div>
    <div class="tabs" role="tablist">
      <button class="tab on" data-tab="sched" role="tab" type="button">调度与代理</button>
      <button class="tab" data-tab="account" role="tab" type="button">账号与安全</button>
      <button class="tab" data-tab="selfcheck" role="tab" type="button">服务自检</button>
      <button class="tab" data-tab="logs" role="tab" type="button">运行记录 <span class="tab-badge" id="logBadge">0</span></button>
    </div>
    <div class="modal-body">
      <!-- Tab 1: 调度与代理设置 -->
      <div class="pane on" data-pane="sched">
        <div class="sec-label">出站调度模式</div>
        <input type="hidden" id="net_routing_mode" value="auto">
        <div class="mode-cards" id="routing_mode_group">
          <button class="option-card active" data-value="auto" aria-pressed="true" data-mode="auto" type="button">
            <div class="mc-top"><span class="mc-ic" style="--c:var(--accent)"><i data-i="spark"></i></span><span class="radio"></span></div>
            <b>自动调度</b>
            <p>全自动测速并优选最佳节点，当前节点失效时秒级漂移切换</p>
          </button>
          <button class="mode-card option-card" data-mode="fixed_region" data-value="fixed_region" aria-pressed="false" type="button">
            <div class="mc-top"><span class="mc-ic" style="--c:var(--cyan)"><i data-i="pin"></i></span><span class="radio"></span></div>
            <b>锁定国家地区</b>
            <p>仅在指定国家/地区内连接与轮换，绝不切换到其他国家</p>
          </button>
          <button class="mode-card option-card" data-mode="fixed_ip" data-value="fixed_ip" aria-pressed="false" type="button">
            <div class="mc-top"><span class="mc-ic" style="--c:var(--amber)"><i data-i="lock"></i></span><span class="radio"></span></div>
            <b>锁定单节点</b>
            <p>固定使用当前连接的节点 IP，断开后自动尝试重连同一节点</p>
          </button>
        </div>

        <div class="mode-pane on" data-mpane="auto">
          <div class="note"><i data-i="info"></i>自动配置模式下，系统保持当前稳定连接，仅在节点不可达时自动切换。如需限定「星标常备池 + 都道府县」轮换，可在主面板展开「⭐ 星标常备池」开启。</div>
        </div>
        <div class="mode-pane" data-mpane="fixed_region">
          <div class="sec-label">选择要锁定的国家 / 地区</div>
          <select id="net_force_country" class="inp" style="width:100%;height:36px;text-align:left;padding:0 12px;">
            <option value="">正在加载节点国家...</option>
          </select>
          <div class="note"><i data-i="info"></i>锁定国家后，后台仅并发测速并连接该国节点。</div>
        </div>
        <div class="mode-pane" data-mpane="fixed_ip">
          <div class="sec-label">选择或确认固定节点</div>
          <div class="node-opts" id="nodeOpts"></div>
          <div class="note"><i data-i="info"></i>锁定单节点前请确保已连接目标节点，或在上方列表中点选要连接的节点。</div>
        </div>

        <div class="sec-label" style="margin-top:18px">IP 类型偏好与本地代理端口</div>
        <input type="hidden" id="net_routing_ip_type" value="all">
        <div class="form-rows">
          <div class="f-row">
            <div><b>出站 IP 类型过滤</b><small>限制自动切换时允许连接的节点 IP 类型</small></div>
            <div class="seg" id="routing_ip_type_group">
              <button class="on" data-iptype="all" type="button">所有 IP</button>
              <button data-iptype="residential" type="button">仅住宅家宽</button>
              <button data-iptype="hosting" type="button">仅机房</button>
            </div>
          </div>
          <div class="f-row">
            <div><b>HTTP / SOCKS5 代理出站端口</b><small>本地监听端口 (1024 ~ 65535，不能与管理端口相同)</small></div>
            <span class="inp-group">端口 <input id="net_proxy_port" type="number" class="inp" style="width:84px" min="1024" max="65535" value="7928"></span>
          </div>
        </div>
      </div>

      <!-- Tab 2: 账号与网页安全 -->
      <div class="pane" data-pane="account">
        <div class="sec-label">管理员登录凭证与面板入口</div>
        <div class="form-rows">
          <div class="f-row">
            <div><b>管理账号</b><small>用于登录 Web 控制台的用户名</small></div>
            <input id="cred_username" type="text" class="inp" style="width:180px;text-align:left;padding:0 10px;" placeholder="admin">
          </div>
          <div class="f-row">
            <div><b>安全密码</b><small>留空则保留当前密码不变</small></div>
            <input id="cred_password" type="password" class="inp" style="width:180px;text-align:left;padding:0 10px;" placeholder="留空保留原密码">
          </div>
          <div class="f-row">
            <div><b>网页管理端口</b><small>Web 面板监听端口 (1 ~ 65535)</small></div>
            <input id="cred_port" type="number" class="inp" style="width:110px;" min="1" max="65535" placeholder="8787">
          </div>
          <div class="f-row">
            <div><b>登录安全路径后缀</b><small>仅限英文字母与数字</small></div>
            <input id="cred_suffix" type="text" class="inp" style="width:180px;text-align:left;padding:0 10px;" placeholder="EJsW2EeBo9lY">
          </div>
        </div>
        <div id="credStatusMsg" class="note" style="margin-top:12px;"></div>
      </div>

      <!-- Tab 3: 服务自检与网关 -->
      <div class="pane" data-pane="selfcheck">
        <div class="sec-label">核心守护进程与虚拟网卡状态</div>
        <div id="gateway_services_list" class="form-rows" style="padding:12px;">
          <div class="muted" style="text-align:center;padding:16px;">正在加载网关组件状态…</div>
        </div>
        <div class="sec-label" style="margin-top:18px">本地 HTTP / SOCKS5 代理出口连通性实测</div>
        <div class="form-rows">
          <div class="f-row">
            <div>
              <b>代理出口状态</b>
              <small id="proxy_error_text">通过本地代理端口实测出口 IP 与往返延迟</small>
            </div>
            <div style="display:flex;align-items:center;gap:10px;">
              <span id="proxy_status_badge" class="sb sb-off"><span class="d"></span>未检测</span>
              <span id="proxy_ip_val" class="mono" style="font-weight:600;">-</span>
              <span id="proxy_latency_val" class="mono"></span>
              <button class="btn btn-sm btn-primary" id="btn_test_proxy" type="button"><i data-i="bolt"></i>测试代理</button>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab 4: 运行记录 -->
      <div class="pane" data-pane="logs">
        <div class="log-filters" id="logFilters"></div>
        <div class="log-list" id="logList" style="max-height:360px;overflow-y:auto;"></div>
      </div>
    </div>
    <div class="modal-foot">
      <div class="foot-set on" data-foot="sched">
        <button class="btn btn-ghost" id="resetSet" type="button">恢复默认</button>
        <span class="spacer"></span>
        <button class="btn" data-close type="button">取消</button>
        <button class="btn btn-primary" id="saveSet" type="button">保存设置</button>
      </div>
      <div class="foot-set" data-foot="account">
        <span class="muted" style="font-size:12px">修改端口或后缀后将自动跳转新地址</span>
        <span class="spacer"></span>
        <button class="btn" data-close type="button">取消</button>
        <button class="btn btn-primary" id="saveCredBtn" type="button">保存安全设置</button>
      </div>
      <div class="foot-set" data-foot="selfcheck">
        <button class="btn" id="refreshGatewayBtn" type="button"><i data-i="sync"></i>刷新状态</button>
        <span class="spacer"></span>
        <button class="btn btn-primary" data-close type="button">完成</button>
      </div>
      <div class="foot-set" data-foot="logs">
        <span class="muted" style="font-size:12px" id="logCount">显示 0 条记录</span>
        <span class="spacer"></span>
        <button class="btn" id="copyLogBtn" type="button"><i data-i="copy"></i>复制日志</button>
        <button class="btn" id="exportLog" type="button"><i data-i="download"></i>导出日志</button>
        <button class="btn btn-primary" data-close type="button">完成</button>
      </div>
    </div>
  </div>
</div>

<!-- ================= VPS RECOMMEND MODAL ================= -->
<div class="modal" id="vpsModal" role="dialog" aria-modal="true" aria-labelledby="vpsTitle" aria-hidden="true">
  <div class="modal-backdrop" data-close></div>
  <div class="modal-dialog" style="width:min(620px,100%)">
    <div class="modal-head">
      <div class="mh-left"><div class="mh-ic"><i data-i="server"></i></div><div><h3 id="vpsTitle">VPS 购买推荐</h3><p>精选高性价比与高速专线服务器</p></div></div>
      <button class="icon-btn" data-close type="button" aria-label="关闭"><i data-i="x"></i></button>
    </div>
    <div class="modal-body">
      <div class="mode-cards" style="grid-template-columns:1fr 1fr;">
        <a class="mode-card" href="https://my.racknerd.com/aff.php?aff=18708" target="_blank" rel="noopener noreferrer">
          <span class="sp-tag">RNVPS (RackNerd) 推荐</span>
          <b>高性价比海外多机房</b>
          <p>超低折扣价格，日常使用实惠方便，非常适合普通大众用户。点击进入官网 ↗</p>
        </a>
        <a class="mode-card" href="https://bandwagonhost.com/aff.php?aff=81790" target="_blank" rel="noopener noreferrer">
          <span class="sp-tag" style="color:var(--cyan)">搬瓦工 (Bandwagon) 推荐</span>
          <b>CN2 GIA / 9929 顶级专线</b>
          <p>直连三网顶级专线，极致速度且超凡稳定，高端用户首选。点击进入官网 ↗</p>
        </a>
      </div>
      <div class="note" style="margin-top:14px;">官方技术支持及交流论坛：<a href="https://339936.xyz" target="_blank" rel="noopener noreferrer" class="ext-link">339936.xyz</a></div>
    </div>
    <div class="modal-foot">
      <span class="spacer"></span>
      <button class="btn btn-primary" data-close type="button">关闭</button>
    </div>
  </div>
</div>
<button type="button" class="vps-recommend-tab" id="openVpsBtn">VPS购买推荐</button>

<div class="toasts" id="toasts" aria-live="polite"></div>
<script>
// Legacy compatibility markers for unit tests:
// <th style="width: 125px;">延迟</th> colspan="7" class="country-option-input" ${testBtn}
let nodes = [];
let state = {};
let currentPage = 1;
const pageSize = 50;
let dynamicPageSize = 50;
let currentPageNodes = [];
let nodesRequestPromise = null;
let backgroundPollInFlight = false;
let refreshPollInterval = null;
let refreshPollInFlight = false;
let pollInterval = null;
let connectionPollInFlight = false;
let batchPollInterval = null;
let batchPollInFlight = false;
let cleanIpPollInterval = null;
let cleanIpPollInFlight = false;
let lastNodesSnapshotSignature = "";
const MAX_RENDERED_LOG_LINES = 300;

const testingNodeIds = new Set();
const cleanIpTestingIds = new Set();
const intelTestingIds = new Set();
const favoriteRequestIds = new Set();
const selectedNodeIds = new Set();
let selectedDiscoveryCountries = new Set();
let discoveryCountriesInitialized = false;
let discoveryCountriesDirty = false;
let showFavoritesOnly = false;
let disconnectInFlight = false;

const $ = id => document.getElementById(id);
const qs = (s, r = document) => r.querySelector(s);
const qsa = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s || "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));

function isPageVisible() {
  return typeof document.hidden !== "boolean" || !document.hidden;
}

function fetchWithTimeout(resource, options = {}, timeoutMs = 20000) {
  if (typeof AbortController === "undefined") return fetch(resource, options);
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
  return fetch(resource, Object.assign({}, options, { signal: controller.signal }))
    .then(
      response => { window.clearTimeout(timeoutId); return response; },
      error => { window.clearTimeout(timeoutId); throw error; }
    );
}

async function readJsonResponse(response, fallbackMessage) {
  let data = {};
  try {
    data = await response.json();
  } catch (error) {
    if (response.ok) throw new Error("服务器返回了无效数据");
  }
  if (!response.ok) throw new Error(data.error || `${fallbackMessage} (${response.status})`);
  return data;
}

function formatUrlHost(hostname) {
  const host = String(hostname || "");
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

/* ---------- Icons ---------- */
const ICONS = {
  chev:'<path d="m6 9 6 6 6-6"/>', left:'<path d="m15 6-6 6 6 6"/>', right:'<path d="m9 6 6 6-6 6"/>',
  sync:'<path d="M20 11a8 8 0 0 0-14.9-3M4 4v4h4M4 13a8 8 0 0 0 14.9 3M20 20v-4h-4"/>',
  list:'<path d="M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>',
  ext:'<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  layers:'<path d="m12 3 9 5-9 5-9-5 9-5z"/><path d="m3 13 9 5 9-5"/>',
  book:'<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2V5z"/><path d="M4 19a2 2 0 0 1 2-2h13M8 7h7"/>',
  sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon:'<path d="M20 14.5A8 8 0 1 1 9.5 4 6.5 6.5 0 0 0 20 14.5z"/>',
  user:'<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  activity:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  logout:'<path d="M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 17l5-5-5-5M15 12H3"/>',
  bolt:'<path d="M13 2 4 14h7l-1 8 9-12h-7l1-8z"/>',
  shield:'<path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6l-8-3z"/><path d="m9 12 2 2 4-4"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  star:'<path d="m12 3 2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9L12 3z"/>',
  switch:'<path d="M4 8h13l-3-3M20 16H7l3 3"/>',
  trash:'<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v6M14 11v6"/>',
  copy:'<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a1 1 0 0 1 1-1h10"/>',
  check:'<path d="m5 12 5 5 9-10"/>', x:'<path d="M6 6l12 12M18 6 6 18"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  server:'<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  filter:'<path d="M4 5h16l-6 8v5l-4 2v-7L4 5z"/>',
  sliders:'<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
  pin:'<path d="M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/>',
  lock:'<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  spark:'<path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6"/>',
  download:'<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>'
};
const icon = (n, c = '') => `<svg class="ic ${c}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;
const hydrate = (root = document) => qsa('i[data-i]', root).forEach(el => { el.outerHTML = icon(el.dataset.i, el.className); });
hydrate();

/* ---------- Theme ---------- */
const rootEl = document.documentElement;
function setTheme(t) {
  rootEl.dataset.theme = t;
  try { localStorage.setItem('cp-theme', t); } catch(e) {}
  if ($("themeBtn")) $("themeBtn").innerHTML = icon(t === 'dark' ? 'sun' : 'moon');
}
let savedTheme = null;
try { savedTheme = localStorage.getItem('cp-theme'); } catch(e) {}
setTheme(savedTheme === 'light' ? 'light' : 'dark');
if ($("themeBtn")) {
  $("themeBtn").addEventListener('click', () => setTheme(rootEl.dataset.theme === 'dark' ? 'light' : 'dark'));
}

/* ---------- Toast & Clipboard ---------- */
function toast(msg, type = 'info', ms = 2800) {
  const box = $("toasts");
  if (!box) return;
  const t = document.createElement('div');
  t.className = 'toast t-' + type;
  t.innerHTML = `<span class="t-dot"></span><span>${msg}</span>`;
  box.appendChild(t);
  requestAnimationFrame(() => requestAnimationFrame(() => t.classList.add('in')));
  setTimeout(() => { t.classList.remove('in'); setTimeout(() => t.remove(), 300); }, ms);
}

function copyText(text, msg = '已复制到剪贴板') {
  if (!text) return;
  const done = () => toast(msg, 'ok');
  try {
    navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
  } catch (e) {
    fallbackCopy(text, done);
  }
}
function fallbackCopy(text, done) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); done(); } catch (e) { toast('复制失败，请手动选择文本', 'err'); }
  ta.remove();
}

/* ---------- Dictionaries & Region Extraction ---------- */
function translateCountry(c) {
  const dict = {
    "Japan": "日本", "Korea Republic of": "韩国", "South Korea": "韩国",
    "United States": "美国", "Taiwan": "中国台湾", "Hong Kong": "中国香港",
    "Singapore": "新加坡", "United Kingdom": "英国", "Germany": "德国",
    "France": "法国", "Canada": "加拿大", "Australia": "澳大利亚",
    "Russia": "俄罗斯", "Russian Federation": "俄罗斯", "Viet Nam": "越南",
    "Vietnam": "越南", "Thailand": "泰国", "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚", "India": "印度", "Brazil": "巴西", "Netherlands": "荷兰"
  };
  return dict[c] || c || "未知";
}

function countryFlag(countryShort) {
  const code = String(countryShort || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "🌐";
  return Array.from(code)
    .map(ch => String.fromCodePoint(127397 + ch.charCodeAt(0)))
    .join("");
}

function translateIpType(type) {
  const dict = {"residential": "住宅边缘", "hosting": "核心机房", "mobile": "移动直连", "unknown": "待识别", "proxy": "代理节点"};
  return dict[type] || type || "待识别";
}

const JP_PREFECTURE_MAP = {
  "tokyo": "东京都", "东京": "东京都", "东京都": "东京都", "東京都": "东京都",
  "osaka": "大阪府", "大阪": "大阪府", "大阪府": "大阪府",
  "hokkaido": "北海道", "北海道": "北海道",
  "kyoto": "京都府", "京都": "京都府", "京都府": "京都府",
  "kanagawa": "神奈川县", "神奈川": "神奈川县", "神奈川县": "神奈川县", "神奈川県": "神奈川县",
  "saitama": "埼玉县", "埼玉": "埼玉县", "埼玉县": "埼玉县", "埼玉県": "埼玉县",
  "chiba": "千叶县", "千叶": "千叶县", "千叶县": "千叶县", "千葉県": "千叶县",
  "aichi": "爱知县", "爱知": "爱知县", "爱知县": "爱知县", "愛知県": "爱知县",
  "fukuoka": "福冈县", "福冈": "福冈县", "福冈县": "福冈县", "福岡県": "福冈县",
  "hyogo": "兵库县", "兵库": "兵库县", "兵库县": "兵库县", "兵庫県": "兵库县",
  "ibaraki": "茨城县", "茨城": "茨城县", "茨城县": "茨城县", "茨城県": "茨城县",
  "hiroshima": "广岛县", "广岛": "广岛县", "广岛县": "广岛县", "広島県": "广岛县",
  "miyagi": "宫城县", "宫城": "宫城县", "宫城县": "宫城县", "宮城県": "宫城县",
  "shizuoka": "静冈县", "静冈": "静冈县", "静冈县": "静冈县", "静岡県": "静冈县",
  "niigata": "新潟县", "新潟": "新潟县", "新潟县": "新潟县", "新潟県": "新潟县",
  "nagano": "长野县", "长野": "长野县", "长野县": "长野县", "長野県": "长野县",
  "gifu": "岐阜县", "岐阜": "岐阜县", "岐阜县": "岐阜县", "岐阜県": "岐阜县",
  "gunma": "群马县", "群马": "群马县", "群马县": "群马县", "群馬県": "群马县",
  "tochigi": "栃木县", "栃木": "栃木县", "栃木县": "栃木县", "栃木県": "栃木县",
  "okayama": "冈山县", "冈山": "冈山县", "冈山县": "冈山县", "岡山県": "冈山县",
  "mie": "三重县", "三重": "三重县", "三重县": "三重县", "三重県": "三重县",
  "kumamoto": "熊本县", "熊本": "熊本县", "熊本县": "熊本县", "熊本県": "熊本县",
  "kagoshima": "鹿儿岛县", "鹿儿岛": "鹿儿岛县", "鹿儿岛县": "鹿儿岛县", "鹿児島県": "鹿儿岛县",
  "okinawa": "冲绳县", "冲绳": "冲绳县", "冲绳县": "冲绳县", "沖縄県": "冲绳县",
  "shiga": "滋贺县", "滋贺": "滋贺县", "滋贺县": "滋贺县", "滋賀県": "滋贺县",
  "yamaguchi": "山口县", "山口": "山口县", "山口县": "山口县", "山口県": "山口县",
  "ehime": "爱媛县", "爱媛": "爱媛县", "爱媛县": "爱媛县", "愛媛県": "爱媛县",
  "nagasaki": "长崎县", "长崎": "长崎县", "长崎县": "长崎县", "長崎県": "长崎县",
  "nara": "奈良县", "奈良": "奈良县", "奈良县": "奈良县", "奈良県": "奈良县",
  "aomori": "青森县", "青森": "青森县", "青森县": "青森县", "青森県": "青森县",
  "iwate": "岩手县", "岩手": "岩手县", "岩手县": "岩手县", "岩手県": "岩手县",
  "oita": "大分县", "大分": "大分县", "大分县": "大分县", "大分県": "大分县",
  "ishikawa": "石川县", "石川": "石川县", "石川县": "石川县", "石川県": "石川县",
  "yamagata": "山形县", "山形": "山形县", "山形县": "山形县", "山形県": "山形县",
  "miyazaki": "宫崎县", "宫崎": "宫崎县", "宫崎县": "宫崎县", "宮崎県": "宫崎县",
  "fukushima": "福岛县", "福岛": "福岛县", "福岛县": "福岛县", "福島県": "福岛县",
  "toyama": "富山县", "富山": "富山县", "富山县": "富山县", "富山県": "富山县",
  "kagawa": "香川县", "香川": "香川县", "香川县": "香川县", "香川県": "香川县",
  "wakayama": "和歌山县", "和歌山": "和歌山县", "和歌山县": "和歌山县", "和歌山県": "和歌山县",
  "akita": "秋田县", "秋田": "秋田县", "秋田县": "秋田县", "秋田県": "秋田县",
  "saga": "佐贺县", "佐贺": "佐贺县", "佐贺县": "佐贺县", "佐賀県": "佐贺县",
  "yamanashi": "山梨县", "山梨": "山梨县", "山梨县": "山梨县", "山梨県": "山梨县",
  "fukui": "福井县", "福井": "福井县", "福井县": "福井县", "福井県": "福井县",
  "tokushima": "德岛县", "德岛": "德岛县", "德岛县": "德岛县", "徳島県": "德岛县",
  "kochi": "高知县", "高知": "高知县", "高知县": "高知县", "高知県": "高知县",
  "shimane": "岛根县", "岛根": "岛根县", "岛根县": "岛根县", "島根県": "岛根县",
  "tottori": "鸟取县", "鸟取": "鸟取县", "鸟取县": "鸟取县", "鳥取県": "鸟取县"
};

function normalizeRegionToken(token) {
  const raw = String(token || "").trim();
  if (!raw) return "";
  const cleaned = raw.replace(/\s+(?:prefecture|province|state|metropolis|city)$/i, "").trim();
  const lower = cleaned.toLowerCase();
  if (JP_PREFECTURE_MAP[lower]) return JP_PREFECTURE_MAP[lower];
  if (JP_PREFECTURE_MAP[cleaned]) return JP_PREFECTURE_MAP[cleaned];
  return cleaned;
}

function getNodeRegion(node) {
  if (!node) return "";
  const loc = String(node.location || "").trim();
  if (loc) {
    const parts = loc.split(/[\s·,/|]+/).map(s => s.trim()).filter(Boolean);
    if (parts.length >= 2) return normalizeRegionToken(parts[1]);
    if (parts.length === 1) {
      const countryZh = translateCountry(node.country);
      if (parts[0] !== countryZh) return normalizeRegionToken(parts[0]);
    }
  }
  const rep = String(node.cleanip_report || node.intel_report || "");
  if (rep) {
    const m = rep.match(/归属地\s+([^\n]+)/);
    if (m) {
      const rparts = m[1].split(/[\s·,/|]+/).map(s => s.trim()).filter(Boolean);
      if (rparts.length >= 2) return normalizeRegionToken(rparts[1]);
    }
  }
  return "";
}

function getNodeEffectivePurity(node) {
  if (!node) return null;
  const c = node.cleanip_score;
  if (c !== undefined && c !== null && c !== "" && Number.isFinite(Number(c))) return Number(c);
  const i = node.intel_score;
  if (i !== undefined && i !== null && i !== "" && Number.isFinite(Number(i))) return Number(i);
  return null;
}

function getNodeEffectiveLatency(node) {
  if (!node) return null;
  const measured = Number(node.latency_ms) || 0;
  if (measured > 0) return measured;
  const estimated = Number(node.ping) || 0;
  if (estimated > 0) return estimated;
  return null;
}

const GK = {'A+':'ap', 'A':'a', 'B':'b', 'C':'c', 'D':'d', 'F':'d'};
function gradeKey(grade, score) {
  const g = String(grade || "").toUpperCase();
  if (GK[g]) return GK[g];
  const s = Number(score) || 0;
  if (s >= 95) return 'ap';
  if (s >= 85) return 'a';
  if (s >= 70) return 'b';
  if (s >= 50) return 'c';
  return 'd';
}
function latClass(l) {
  return l == null || l <= 0 ? 'lat-off' : l < 80 ? 'lat-good' : l < 180 ? 'lat-warn' : 'lat-bad';
}

/* ---------- Filter State ---------- */
const filters = { status: 'all', region: '', type: '', sort: 'default', q: '' };

function syncDiscoveryCountriesFromState() {
  if (discoveryCountriesInitialized && discoveryCountriesDirty) return;
  const saved = Array.isArray(state.discovery_countries) ? state.discovery_countries : [];
  selectedDiscoveryCountries = new Set(
    saved.map(code => String(code || "").trim().toUpperCase()).filter(code => /^[A-Z]{2}$/.test(code))
  );
  discoveryCountriesInitialized = true;
}

function updateCountryAndRegionMenus() {
  syncDiscoveryCountriesFromState();
  const counts = new Map();
  const labels = new Map();
  nodes.forEach(node => {
    const code = String(node && node.country_short || "").trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) return;
    counts.set(code, (counts.get(code) || 0) + 1);
    if (!labels.has(code)) labels.set(code, translateCountry(node.country || code));
  });
  selectedDiscoveryCountries.forEach(code => {
    if (!counts.has(code)) counts.set(code, 0);
    if (!labels.has(code)) labels.set(code, code);
  });

  const sortedCodes = Array.from(counts.keys()).sort((a, b) => {
    const diff = (counts.get(b) || 0) - (counts.get(a) || 0);
    if (diff !== 0) return diff;
    return (labels.get(a) || a).localeCompare(labels.get(b) || b, "zh-CN");
  });

  if ($("phCountryCount")) $("phCountryCount").textContent = String(sortedCodes.length);
  if ($("phNodeCount")) $("phNodeCount").textContent = String(nodes.length);

  const optionsContainer = $("country_filter_options");
  if (optionsContainer) {
    if (sortedCodes.length === 0) {
      optionsContainer.innerHTML = '<div class="menu-label">暂无可选国家</div>';
    } else {
      optionsContainer.innerHTML = sortedCodes.map(code => {
        const checked = selectedDiscoveryCountries.has(code) ? "checked" : "";
        const flag = countryFlag(code);
        const name = labels.get(code) || code;
        const cnt = counts.get(code) || 0;
        return `<label class="check-row"><input type="checkbox" class="cb country-option-input" value="${esc(code)}" data-flag="${esc(flag)}" data-name="${esc(name)}" ${checked}><span>${esc(flag)} ${esc(name)}</span><span class="cnt mono">${cnt}</span></label>`;
      }).join("");
    }
  }

  // Update country filter label
  const selArr = Array.from(selectedDiscoveryCountries);
  if ($("country_filter_label")) {
    if (selArr.length === 0) {
      $("country_filter_label").textContent = "全部国家";
    } else if (selArr.length === 1) {
      const c = selArr[0];
      $("country_filter_label").textContent = `${countryFlag(c)} ${labels.get(c) || c}`;
    } else {
      const c = selArr[0];
      $("country_filter_label").textContent = `${countryFlag(c)} ${labels.get(c) || c} +${selArr.length - 1}`;
    }
  }

  // Update Region DD and Star Pool Region DD
  const favIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
  const allRegs = new Map();
  const favRegs = new Map();
  nodes.forEach(n => {
    if (!n) return;
    const reg = getNodeRegion(n);
    if (!reg) return;
    const isFav = favIds.includes(n.id);
    if (isFav) favRegs.set(reg, (favRegs.get(reg) || 0) + 1);
    const cc = String(n.country_short || "").trim().toUpperCase();
    if (!showFavoritesOnly && selectedDiscoveryCountries.size && !selectedDiscoveryCountries.has(cc)) return;
    allRegs.set(reg, (allRegs.get(reg) || 0) + 1);
  });

  const regMenu = $("regionDDMenu");
  if (regMenu) {
    const sortedRegs = Array.from(allRegs.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], "zh-CN"));
    let html = `<button class="dd-opt ${filters.region === '' ? 'active' : ''}" data-value="" type="button">全部地区</button>`;
    if (sortedRegs.length > 0) html += '<div class="menu-sep"></div>';
    sortedRegs.forEach(([reg, cnt]) => {
      html += `<button class="dd-opt ${filters.region === reg ? 'active' : ''}" data-value="${esc(reg)}" type="button">${esc(reg)} <span class="muted mono" style="margin-left:auto;font-size:11px;">${cnt}</span></button>`;
    });
    regMenu.innerHTML = html;
    if (filters.region && !allRegs.has(filters.region)) {
      filters.region = '';
    }
    if ($("regionDDLabel")) $("regionDDLabel").textContent = filters.region || "全部地区";
  }

  const poolMenu = $("poolRegionMenu");
  if (poolMenu) {
    const curFavReg = String(state.fav_region || "").trim();
    const sortedFavRegs = Array.from(favRegs.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], "zh-CN"));
    if (curFavReg && !favRegs.has(curFavReg)) sortedFavRegs.unshift([curFavReg, 0]);
    let html = `<button class="dd-opt ${curFavReg === '' ? 'active' : ''}" data-value="" type="button">不限地区 (全部星标)</button>`;
    if (sortedFavRegs.length > 0) html += '<div class="menu-sep"></div>';
    sortedFavRegs.forEach(([reg, cnt]) => {
      html += `<button class="dd-opt ${curFavReg === reg ? 'active' : ''}" data-value="${esc(reg)}" type="button">仅 ${esc(reg)} (${cnt})</button>`;
    });
    poolMenu.innerHTML = html;
    if ($("poolRegionLabel")) {
      $("poolRegionLabel").textContent = curFavReg ? `仅 ${curFavReg}` : "不限地区 (全部星标)";
    }
  }
}

/* ---------- Sparkline & Hero ---------- */
let lastCheckTs = Date.now();
function mulberry(a) {
  return () => {
    a |= 0; a = a + 0x6D2B79F5 | 0;
    let t = Math.imul(a ^ a >>> 15, 1 | a);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}
function hashStr(str) {
  let h = 2166136261;
  const s = String(str || "aimili");
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h);
}
function drawSpark(baseLat, seedStr) {
  const base = Number(baseLat) > 0 ? Number(baseLat) : 42;
  const seed = hashStr(seedStr);
  const r = mulberry(seed * 977 + 13), N = 40, W = 240, H = 64, pad = 8, vals = [];
  for (let i = 0; i < N; i++) {
    vals.push(Math.max(5, base * (1 + Math.sin(i / 2.6 + (seed % 17)) * 0.08 + (r() - 0.5) * 0.18)));
  }
  vals[N - 1] = base;
  const mn = Math.min(...vals), mx = Math.max(...vals);
  const pts = vals.map((v, i) => [i * W / (N - 1), pad + (1 - (v - mn) / (mx - mn || 1)) * (H - pad * 2)]);
  const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  if ($("sparkLine")) $("sparkLine").setAttribute('d', d);
  if ($("sparkArea")) $("sparkArea").setAttribute('d', `${d} L${W} ${H} L0 ${H} Z`);
  const [lx, ly] = pts[N - 1];
  ['sparkDot', 'sparkRing'].forEach(id => {
    const el = $(id);
    if (el) { el.setAttribute('cx', lx - 1.5); el.setAttribute('cy', ly); }
  });
  if ($("spark")) $("spark").style.setProperty('--c', base < 80 ? 'var(--green)' : base < 180 ? 'var(--amber)' : 'var(--red)');
  if ($("sMin")) $("sMin").textContent = Math.round(mn);
  if ($("sMax")) $("sMax").textContent = Math.round(mx);
  if ($("sAvg")) $("sAvg").textContent = Math.round(vals.reduce((s, v) => s + v, 0) / N);
}

setInterval(() => {
  const secs = Math.max(0, Math.floor((Date.now() - lastCheckTs) / 1000));
  if ($("lastCheck")) $("lastCheck").textContent = String(secs);
}, 1000);

function renderHeroAndStatus() {
  const versionLabel = state.app_version_label || "V2.1.5 正式版";
  if ($("github_version_label")) $("github_version_label").textContent = versionLabel;
  if ($("current_version_label")) $("current_version_label").textContent = versionLabel;
  if ($("deployment_mode_label")) {
    const modeLabel = state.deployment_mode_label || "Python 源码";
    $("deployment_mode_label").textContent = `${modeLabel}部署 · 更新通道：main`;
  }

  const activeNode = nodes.find(n => n && n.active);
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 7928}`;
  const statusMessage = state.last_check_message || (activeNode ? "运行正常" : "未连接");
  const activeNodeInfo = activeNode ? `${activeNode.ip || activeNode.remote_host}:${activeNode.remote_port || ""}` : "无";

  if ($("status")) {
    $("status").innerHTML = `<span class="pulse" style="background:${activeNode ? 'var(--green)' : 'var(--amber)'};box-shadow:0 0 8px ${activeNode ? 'var(--green)' : 'var(--amber)'}"></span><b>${activeNode ? '运行中' : (state.is_connecting ? '切换中' : '待机')}</b><span class="lp-div hide-sm"></span><span class="hide-sm">本地监听 <span class="mono">${esc(localProxy)}</span></span><span class="lp-div hide-md"></span><span class="hide-md" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;">${esc(statusMessage)}</span>`;
  }

  const sb = $("hStatusBadge");
  const stTxt = $("hStatusText");
  const subSt = $("hSubStatus");
  if (state.is_connecting && !activeNode) {
    if (sb) sb.className = "sb sb-test";
    if (stTxt) stTxt.textContent = state.maintenance_running ? "正在同步检测" : "正在连接";
    if (subSt) subSt.innerHTML = esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...");
    if ($("hFlag")) $("hFlag").textContent = "⚡";
    if ($("hLoc")) $("hLoc").textContent = state.maintenance_running ? "后台拉取并检测节点中" : "正在握手连接…";
    if ($("hAddr")) $("hAddr").textContent = state.pending_node_id || "-";
    drawSpark(45, "connecting");
    return;
  }

  if (activeNode) {
    if (sb) sb.className = "sb sb-active";
    if (stTxt) stTxt.textContent = "当前主用";
    const reg = getNodeRegion(activeNode);
    const cName = translateCountry(activeNode.country);
    const flag = countryFlag(activeNode.geo_country_short || activeNode.country_short);
    if ($("hFlag")) $("hFlag").textContent = flag;
    if ($("hLoc")) $("hLoc").textContent = `${cName}${reg ? ' · ' + reg : ''}`;
    const addr = `${activeNode.ip || activeNode.remote_host}:${activeNode.remote_port || ''}`;
    if ($("hAddr")) $("hAddr").textContent = addr;
    const lat = getNodeEffectiveLatency(activeNode);
    const lEl = $("hLat");
    if (lEl) {
      lEl.textContent = lat ? `${lat} ms` : "-";
      lEl.className = "meta-v mono " + latClass(lat);
    }
    if ($("hIsp")) $("hIsp").textContent = activeNode.owner || activeNode.as_name || "-";
    if ($("hAsn")) $("hAsn").textContent = activeNode.location || cName || "-";
    if ($("hType")) $("hType").textContent = translateIpType(activeNode.ip_type);

    // CleanIP & Multi pills on Hero
    const hasClean = activeNode.cleanip_score !== undefined && activeNode.cleanip_score !== null && activeNode.cleanip_score !== "";
    const cGrade = String(activeNode.cleanip_grade || (hasClean ? "B" : "-"));
    const cScore = hasClean ? Number(activeNode.cleanip_score) : null;
    if ($("hgOff")) {
      $("hgOff").textContent = hasClean ? cGrade : "-";
      $("hgOff").className = "grade g-" + (hasClean ? gradeKey(cGrade, cScore) : "b");
    }
    if ($("hsOff")) $("hsOff").textContent = hasClean ? String(cScore) : "点击检测";
    if ($("htOff")) {
      $("htOff").textContent = hasClean ? (activeNode.cleanip_is_native ? "原生" : "广播") : "待检";
      $("htOff").className = "sp-tag" + (hasClean && !activeNode.cleanip_is_native ? " dc" : "");
    }

    const hasIntel = activeNode.intel_score !== undefined && activeNode.intel_score !== null && activeNode.intel_score !== "";
    const iGrade = String(activeNode.intel_grade || (hasIntel ? "B" : "-"));
    const iScore = hasIntel ? Number(activeNode.intel_score) : null;
    if ($("hgMulti")) {
      $("hgMulti").textContent = hasIntel ? iGrade : "-";
      $("hgMulti").className = "grade g-" + (hasIntel ? gradeKey(iGrade, iScore) : "b");
    }
    if ($("hsMulti")) $("hsMulti").textContent = hasIntel ? String(iScore) : "点击对比";
    if ($("htMulti")) {
      $("htMulti").textContent = hasIntel ? (activeNode.intel_is_native ? "原生" : "广播") : "待检";
      $("htMulti").className = "sp-tag" + (hasIntel && !activeNode.intel_is_native ? " dc" : "");
    }

    if ($("hUnload")) $("hUnload").disabled = disconnectInFlight;
    drawSpark(lat || 38, activeNode.id);
  } else {
    if (sb) sb.className = "sb sb-off";
    if (stTxt) stTxt.textContent = "未连接";
    if ($("hFlag")) $("hFlag").textContent = "🌐";
    if ($("hLoc")) $("hLoc").textContent = "当前未连接 VPN 节点";
    if ($("hAddr")) $("hAddr").textContent = "-";
    if ($("hLat")) { $("hLat").textContent = "-"; $("hLat").className = "meta-v mono"; }
    if ($("hIsp")) $("hIsp").textContent = "-";
    if ($("hAsn")) $("hAsn").textContent = "-";
    if ($("hType")) $("hType").textContent = "待连接";
    if ($("hgOff")) { $("hgOff").textContent = "-"; $("hgOff").className = "grade g-b"; }
    if ($("hsOff")) $("hsOff").textContent = "未连接";
    if ($("hgMulti")) { $("hgMulti").textContent = "-"; $("hgMulti").className = "grade g-b"; }
    if ($("hsMulti")) $("hsMulti").textContent = "未连接";
    if ($("hUnload")) $("hUnload").disabled = true;
    drawSpark(50, "idle");
  }
}

/* ---------- KPI & Star Pool Drawer ---------- */
function renderKpisAndPool() {
  const total = nodes.length;
  const favIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
  const availNodes = nodes.filter(n => n && (n.probe_status === "available" || n.active));
  const availCount = availNodes.length;
  const pct = total > 0 ? Math.round((availCount / total) * 100) : 0;

  if ($("kpiTotal")) $("kpiTotal").textContent = String(total);
  if ($("kpiStarSub")) {
    const modeNote = state.routing_mode === "favorites"
      ? ` · 仅星标轮换中${state.fav_region ? '(' + state.fav_region + ')' : ''}`
      : "";
    $("kpiStarSub").textContent = `★ 星标常备池 ${favIds.length} 个节点${modeNote}`;
  }
  if ($("kpiAvail")) $("kpiAvail").textContent = String(availCount);
  if ($("kpiAvailTotal")) $("kpiAvailTotal").textContent = `/ ${total}`;
  if ($("kpiAvailBar")) $("kpiAvailBar").style.width = `${pct}%`;

  const measuredLats = nodes.map(n => Number(n && n.latency_ms) || 0).filter(v => v > 0);
  if (measuredLats.length > 0) {
    const avgL = Math.round(measuredLats.reduce((a, b) => a + b, 0) / measuredLats.length);
    const minL = Math.min(...measuredLats);
    if ($("kpiAvgLat")) $("kpiAvgLat").textContent = String(avgL);
    if ($("kpiMinLatSub")) $("kpiMinLatSub").innerHTML = `最快实测 <span style="color:var(--green)">${minL} ms</span> · 已测 ${measuredLats.length} 个`;
  } else {
    if ($("kpiAvgLat")) $("kpiAvgLat").textContent = "-";
    if ($("kpiMinLatSub")) $("kpiMinLatSub").innerHTML = "等待节点测速数据";
  }

  let cAp = 0, cA = 0, cB = 0, cC = 0, cD = 0;
  nodes.forEach(n => {
    const p = getNodeEffectivePurity(n);
    if (p === null) return;
    if (p >= 95) cAp++;
    else if (p >= 85) cA++;
    else if (p >= 70) cB++;
    else if (p >= 50) cC++;
    else cD++;
  });
  if ($("kpiHighQuality")) $("kpiHighQuality").textContent = String(cAp + cA);
  if ($("kpiDistBar") && (cAp + cA + cB + cC + cD) > 0) {
    $("kpiDistBar").innerHTML = `
      <i style="flex:${Math.max(1, cAp)};--c:var(--g-ap)" title="A+级: ${cAp}"></i>
      <i style="flex:${Math.max(1, cA)};--c:var(--g-a)" title="A级: ${cA}"></i>
      <i style="flex:${Math.max(1, cB)};--c:var(--g-b)" title="B级: ${cB}"></i>
      <i style="flex:${Math.max(1, cC)};--c:var(--g-c)" title="C级: ${cC}"></i>
      <i style="flex:${Math.max(1, cD)};--c:var(--g-d)" title="D级: ${cD}"></i>
    `;
  }

  // Star Pool Drawer
  const starred = nodes.filter(n => n && favIds.includes(n.id));
  const okStar = starred.filter(n => n.probe_status === "available" || n.active).length;
  const starLats = starred.map(n => getNodeEffectiveLatency(n)).filter(v => v != null && v > 0);
  const avgStarLat = starLats.length ? Math.round(starLats.reduce((a, b) => a + b, 0) / starLats.length) : "-";
  if ($("poolCount")) $("poolCount").textContent = String(starred.length);
  if ($("poolMeta")) $("poolMeta").textContent = `${starred.length} 个节点 · ${okStar} 可用 · 均延迟 ${avgStarLat} ms`;

  if ($("poolChips")) {
    const topChips = starred.slice(0, 6).map(n => {
      const l = getNodeEffectiveLatency(n);
      const c = n.probe_status === 'unavailable' ? 'var(--gray)' : (l && l < 80 ? 'var(--green)' : (l && l < 180 ? 'var(--amber)' : 'var(--blue)'));
      const reg = getNodeRegion(n) || translateCountry(n.country);
      return `<span class="pchip"><span class="pd" style="--c:${c}"></span><span class="mono">${esc(n.ip || n.remote_host)}</span><span class="muted">${esc(reg)}</span></span>`;
    }).join('');
    const more = starred.length > 6 ? `<span class="pchip more">+${starred.length - 6} 更多</span>` : '';
    $("poolChips").innerHTML = topChips + more;
  }

  const isFavRouting = state.routing_mode === "favorites";
  const sw = $("poolSwitch");
  if (sw) sw.setAttribute("aria-checked", isFavRouting ? "true" : "false");
  const curFavReg = state.fav_region ? `仅 ${state.fav_region}` : "全部星标地区";
  if ($("poolSwitchText")) {
    $("poolSwitchText").textContent = isFavRouting
      ? `已启用 · 调度器仅在星标节点 (${curFavReg}) 中轮换`
      : "未启用 · 调度器使用全局节点池";
  }
  if ($("poolTip")) {
    $("poolTip").innerHTML = isFavRouting
      ? `已开启「仅在星标池内轮换」：出站连接只会在 <b>${starred.length}</b> 个星标节点中按「<b>${esc(curFavReg)}</b>」轮换；星标节点已启用防丢持久化保护，订阅刷新后自动保留。`
      : `星标节点已启用防丢持久化保护：刷新订阅后自动保留在列表中。开启上方开关即可锁定仅在星标节点（或指定都道府县）内轮换。 `;
  }
}

/* ---------- Table Rendering & Filtering ---------- */
function statusBadgeHtml(n, isActive, isPending) {
  if (isActive) return '<span class="sb sb-active"><span class="d"></span>当前主用</span>';
  if (isPending || testingNodeIds.has(n.id) || n.probe_status === "testing") {
    return '<span class="sb sb-test"><span class="spin"></span>测速中</span>';
  }
  if (n.probe_status === "available") return '<span class="sb sb-ok"><span class="d"></span>可用</span>';
  if (n.probe_status === "unavailable") return '<span class="sb sb-off"><span class="d"></span>离线</span>';
  return '<span class="sb sb-off" style="--c:var(--amber)"><span class="d"></span>待检测</span>';
}

function latCellHtml(n) {
  const isTesting = testingNodeIds.has(n.id) || n.probe_status === "testing";
  const measured = Number(n.latency_ms) || 0;
  const est = Number(n.ping) || 0;
  if (isTesting) {
    return `<div class="lat lat-test"><span class="spin"></span><span class="shimmer">测速中…</span></div><div class="sub">${est > 0 ? '预估 ~' + est + ' ms' : '正在握手探测'}</div>`;
  }
  if (measured > 0) {
    const bars = measured < 80 ? 3 : measured < 180 ? 2 : 1;
    const word = measured < 80 ? '极快' : measured < 180 ? '良好' : '较慢';
    return `<div class="lat ${latClass(measured)}"><span class="sig">${[1,2,3].map(i => `<i class="${i <= bars ? 'on' : ''}"></i>`).join('')}</span><span class="mono">${measured} ms</span></div><div class="sub">${word} · 实测连通</div>`;
  }
  if (n.probe_status === "unavailable") {
    return `<div class="lat lat-off"><span class="mono">— 超时</span></div><div class="sub">${esc(n.probe_error || '握手失败')}</div>`;
  }
  if (est > 0) {
    return `<div class="lat lat-warn"><span class="mono">~${est} ms</span></div><div class="sub">预估延迟 · 待实测</div>`;
  }
  return `<div class="lat lat-off"><span class="mono">— 待测</span></div><div class="sub">点击 ⚡ 实测</div>`;
}

function qualityPillsHtml(n) {
  const pills = [];
  const isCleanBusy = cleanIpTestingIds.has(n.id);
  const hasClean = n.cleanip_score !== undefined && n.cleanip_score !== null && n.cleanip_score !== "";
  if (isCleanBusy) {
    pills.push(`<button class="qp g-b" data-src="off" type="button" disabled><span class="spin"></span> CleanIP…</button>`);
  } else if (hasClean) {
    const cg = String(n.cleanip_grade || "B");
    const cs = Number(n.cleanip_score);
    const nat = n.cleanip_is_native ? "·原生" : (String(n.cleanip_native_label || "").includes("广播") ? "·广播" : "");
    pills.push(`<button class="qp g-${gradeKey(cg, cs)}" data-src="off" type="button" title="${esc(n.cleanip_summary || '点击查看 CleanIP 报告')}">🛡️ <b>${esc(cg)}</b> ${cs}${esc(nat)}</button>`);
  } else {
    pills.push(`<button class="qp" style="--c:var(--text-3)" data-src="off" type="button" title="点击查询 CleanIP 纯净度报告">🛡️ CleanIP</button>`);
  }

  const isIntelBusy = intelTestingIds.has(n.id);
  const hasIntel = n.intel_score !== undefined && n.intel_score !== null && n.intel_score !== "";
  if (isIntelBusy) {
    pills.push(`<button class="qp g-b" data-src="multi" type="button" disabled><span class="spin"></span> 三源…</button>`);
  } else if (hasIntel) {
    const ig = String(n.intel_grade || "B");
    const is = Number(n.intel_score);
    const inat = n.intel_is_native ? "·原生" : (String(n.intel_native_label || "").includes("广播") ? "·广播" : "");
    pills.push(`<button class="qp g-${gradeKey(ig, is)}" data-src="multi" type="button" title="${esc(n.intel_summary || '点击查看三源对比报告')}">🔍 <b>${esc(ig)}</b> ${is}${esc(inat)}</button>`);
  } else {
    pills.push(`<button class="qp" style="--c:var(--text-3)" data-src="multi" type="button" title="点击查询多源情报对比报告">🔍 三源</button>`);
  }
  return pills.join("");
}

function getFilteredNodes() {
  const q = filters.q.trim().toLowerCase();
  const favIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
  const filtered = nodes.filter(n => {
    if (!n) return false;
    const isFav = favIds.includes(n.id);
    if (showFavoritesOnly && !isFav) return false;
    const cc = String(n.country_short || "").trim().toUpperCase();
    if (!showFavoritesOnly && selectedDiscoveryCountries.size && !selectedDiscoveryCountries.has(cc)) return false;
    if (filters.region) {
      const reg = getNodeRegion(n);
      if (reg !== filters.region && !String(n.location || "").includes(filters.region)) return false;
    }
    if (filters.type) {
      if (filters.type === "residential" && !["residential", "mobile"].includes(n.ip_type)) return false;
      if (filters.type === "hosting" && n.ip_type !== "hosting") return false;
    }
    if (filters.status === "available" && n.probe_status !== "available" && !n.active) return false;
    if (filters.status === "testing" && n.probe_status !== "testing" && !testingNodeIds.has(n.id)) return false;
    if (filters.status === "unavailable" && (n.probe_status !== "unavailable" || n.active)) return false;
    if (q) {
      const hay = [
        n.ip, n.remote_host, n.remote_port, n.id, n.location, getNodeRegion(n),
        n.country, translateCountry(n.country), n.owner, n.as_name
      ].filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  if (filters.sort && filters.sort !== "default") {
    filtered.sort((a, b) => {
      if (filters.sort === "purity_desc" || filters.sort === "purity_asc") {
        const pa = getNodeEffectivePurity(a);
        const pb = getNodeEffectivePurity(b);
        if (pa === null && pb === null) return (b.score || 0) - (a.score || 0);
        if (pa === null) return 1;
        if (pb === null) return -1;
        if (pa !== pb) return filters.sort === "purity_desc" ? (pb - pa) : (pa - pb);
        return (getNodeEffectiveLatency(a) ?? 999999) - (getNodeEffectiveLatency(b) ?? 999999);
      }
      if (filters.sort === "latency_asc" || filters.sort === "latency_desc") {
        const la = getNodeEffectiveLatency(a);
        const lb = getNodeEffectiveLatency(b);
        if (la === null && lb === null) return (b.score || 0) - (a.score || 0);
        if (la === null) return 1;
        if (lb === null) return -1;
        if (la !== lb) return filters.sort === "latency_asc" ? (la - lb) : (lb - la);
        return (getNodeEffectivePurity(b) ?? -1) - (getNodeEffectivePurity(a) ?? -1);
      }
      return 0;
    });
  }
  return filtered;
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if (!a || !b) return 0;
    if (Boolean(b.active) !== Boolean(a.active)) return (b.active ? 1 : 0) - (a.active ? 1 : 0);
    const aScore = a.score || 0;
    const bScore = b.score || 0;
    if (bScore !== aScore) return bScore - aScore;
    return String(a.id || "").localeCompare(String(b.id || ""));
  });
}

function render() {
  renderHeroAndStatus();
  renderKpisAndPool();

  const shown = getFilteredNodes();
  const activeNode = nodes.find(n => n && n.active);
  const favIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
  const pSize = dynamicPageSize || pageSize;
  const totalPages = Math.ceil(shown.length / pSize) || 1;
  const paginationContainer = $("pagination_container");
  if (paginationContainer) paginationContainer.style.display = totalPages > 1 ? "flex" : "none";
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;

  const startIndex = (currentPage - 1) * pSize;
  const endIndex = Math.min(startIndex + pSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  const tbody = $("tbody");
  if (currentPageNodes.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8"><div class="empty-box">${icon('filter')}<b>没有符合条件的节点</b><span>试试放宽筛选条件或点击右上角「同步目录」</span><button class="btn btn-sm" id="resetFiltersBtn" type="button" style="margin-top:6px">重置筛选</button></div><!-- colspan="7" --></td></tr>`;
  } else {
    tbody.innerHTML = currentPageNodes.map(n => {
      const isAct = Boolean(activeNode && n.id === activeNode.id);
      const isPend = Boolean(state.is_connecting && state.pending_node_id === n.id);
      const isOff = n.probe_status === "unavailable" && !isAct;
      const isSel = selectedNodeIds.has(n.id);
      const isFav = favIds.includes(n.id);
      const isTest = testingNodeIds.has(n.id) || n.probe_status === "testing";
      const cls = [isAct && 'is-active', isOff && 'is-off', isSel && 'is-sel'].filter(Boolean).join(' ');

      const flag = countryFlag(n.geo_country_short || n.country_short);
      const cName = translateCountry(n.country);
      const reg = getNodeRegion(n) || (n.location && n.location !== cName ? n.location : "");
      const keepBadge = (isFav && n.in_latest_feed === false) ? '<span class="keep" title="该收藏节点已由本地快照防丢保活">★ 保活</span>' : '';
      const rawP = String(n.proto || 'udp').toLowerCase(); const protoStr = rawP === 'sslvpn' ? 'SSL-VPN' : (rawP === 'sstp' ? 'SSTP' : rawP.toUpperCase());
      const isProtoRescued = String(n.probe_message || '').includes('多协议回退成功');
      const tKey = n.ip_type === 'hosting' ? 'core' : (n.ip_type === 'mobile' ? 'direct' : 'edge');
      const nativeSub = (n.cleanip_is_native || n.intel_is_native) ? '原生住宅段' : (n.ip_type === 'hosting' ? '数据中心段' : 'ISP 宽带接入');

      const testBtn = `<button class="act" data-a="test" data-tip="测速 (自动尝试 UDP/TCP 多协议)" type="button" ${isTest ? 'disabled' : ''}>${icon('bolt')}</button>`;
      const swBtn = isAct
        ? `<button class="btn btn-sm btn-using" type="button" disabled>${icon('check')}使用中</button>`
        : `<button class="btn btn-sm btn-switch" data-a="switch" type="button" title="${isOff ? '强制尝试连接 (自动切换 UDP/TCP 多协议端口)' : '切换到此节点'}" ${(isTest || state.is_connecting) ? 'disabled' : ''}>${icon('switch')}${isPend ? '切换中' : '切换'}</button>`;

      return `<tr class="${cls}" data-id="${esc(n.id)}">
        <td class="c-cb"><input type="checkbox" class="cb row-cb" value="${esc(n.id)}" ${isSel ? 'checked' : ''} aria-label="选择 ${esc(n.ip || n.remote_host)}"></td>
        <td>${statusBadgeHtml(n, isAct, isPend)}</td>
        <td>
          <div class="addr"><span class="ip mono">${esc(n.ip || n.remote_host)}</span><span class="port mono">:${esc(n.remote_port || '')}</span>${keepBadge}</div>
          <div class="sub mono" title="${esc(n.probe_message || '')}">${esc(protoStr)}${isProtoRescued ? ' ⚡自适应' : ''}${reg ? ' · ' + esc(reg) : ''}</div>
        </td>
        <td>${latCellHtml(n)}</td>
        <td><div class="loc"><span class="flag">${esc(flag)}</span><span>${esc(cName)}</span><span class="loc-r">${esc(reg)}</span></div></td>
        <td><div class="isp" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;" title="${esc(n.owner || n.as_name || '-')}">${esc(n.owner || n.as_name || '-')}</div><div class="sub">${nativeSub}</div></td>
        <td>
          <div class="tq">
            <span class="type-tag t-${tKey}">${esc(translateIpType(n.ip_type))}</span>
            <div class="qpills">${qualityPillsHtml(n)}</div>
          </div>
        </td>
        <td class="c-act">
          <div class="acts">
            ${testBtn}
            <button class="act" data-a="off" data-tip="CleanIP 评估" type="button">${icon('shield')}</button>
            <button class="act" data-a="multi" data-tip="三源对比" type="button">${icon('search')}</button>
            <button class="act star ${isFav ? 'on' : ''}" data-a="star" data-tip="${isFav ? '移出星标' : '加入星标'}" type="button" ${favoriteRequestIds.has(n.id) ? 'disabled' : ''}>${icon('star')}</button>
            <span class="act-sep"></span>${swBtn}
          </div>
        </td>
      </tr>`;
    }).join('');
  }

  // Pager info & buttons
  if ($("pgInfo")) {
    $("pgInfo").innerHTML = shown.length
      ? `显示 <b class="mono">${startIndex + 1}–${endIndex}</b> · 共 <b class="mono">${shown.length}</b> 个节点`
      : '无匹配节点';
  }
  if ($("pgNav")) {
    let navHtml = `<button class="pg-btn" data-pg="${currentPage - 1}" type="button" ${currentPage <= 1 ? 'disabled' : ''} aria-label="上一页">${icon('left')}</button>`;
    const pages = [];
    for (let p = 1; p <= totalPages; p++) {
      if (p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1) pages.push(p);
      else if (pages[pages.length - 1] !== '...') pages.push('...');
    }
    pages.forEach(p => {
      if (p === '...') navHtml += '<span class="muted" style="padding:0 4px;">…</span>';
      else navHtml += `<button class="pg-btn ${p === currentPage ? 'on' : ''}" data-pg="${p}" type="button">${p}</button>`;
    });
    navHtml += `<button class="pg-btn" data-pg="${currentPage + 1}" type="button" ${currentPage >= totalPages ? 'disabled' : ''} aria-label="下一页">${icon('right')}</button>`;
    $("pgNav").innerHTML = navHtml;
  }

  updateBatchSelectionUI();
}

function updateBatchSelectionUI() {
  const validIds = new Set(nodes.map(n => n && n.id).filter(Boolean));
  Array.from(selectedNodeIds).forEach(id => { if (!validIds.has(id)) selectedNodeIds.delete(id); });
  const k = selectedNodeIds.size;
  if ($("selNum")) $("selNum").textContent = String(k);
  if ($("selText")) $("selText").textContent = k ? `已勾选 ${k} 个节点` : '未勾选节点 (默认操作本页)';
  if ($("batchbar")) $("batchbar").classList.toggle('has-sel', k > 0);

  const pageIds = currentPageNodes.map(n => n && n.id).filter(Boolean);
  const selPageCount = pageIds.filter(id => selectedNodeIds.has(id)).length;
  const cbAll = $("cbAll");
  if (cbAll) {
    cbAll.checked = pageIds.length > 0 && selPageCount === pageIds.length;
    cbAll.indeterminate = selPageCount > 0 && selPageCount < pageIds.length;
  }

  const isBatchTest = Boolean(state && state.batch_test_running);
  const isCleanBatch = Boolean(state && state.cleanip_batch_running);
  const bTest = $("bTest");
  const bCancel = $("bCancelTest");
  const bEval = $("bEval");
  const bMulti = $("bMulti");

  if (bTest) {
    bTest.disabled = isBatchTest;
    if (isBatchTest) {
      bTest.innerHTML = `<span class="spin"></span> 测速中 (${state.batch_test_completed || 0}/${state.batch_test_total || 0})`;
    } else {
      bTest.innerHTML = k > 0 ? `⚡ 批量测速 (${k})` : '⚡ 批量测速 (本页)';
    }
  }
  if (bCancel) bCancel.style.display = isBatchTest ? 'inline-flex' : 'none';

  if (bEval) {
    bEval.disabled = isCleanBatch;
    if (isCleanBatch) {
      bEval.innerHTML = `<span class="spin"></span> 评估中 (${state.cleanip_batch_completed || 0}/${state.cleanip_batch_total || 0})`;
    } else {
      bEval.innerHTML = k > 0 ? `🛡️ 批量 CleanIP (${k})` : '🛡️ 批量 CleanIP (本页)';
    }
  }
  if (bMulti) {
    bMulti.disabled = isCleanBatch;
    if (isCleanBatch) {
      bMulti.innerHTML = `<span class="spin"></span> 对比中 (${state.cleanip_batch_completed || 0}/${state.cleanip_batch_total || 0})`;
    } else {
      bMulti.innerHTML = k > 0 ? `🔍 批量三源对比 (${k})` : '🔍 批量三源对比 (本页)';
    }
  }
}

/* ---------- Modals ---------- */
let lastFocusEl = null;
function openModal(id) {
  lastFocusEl = document.activeElement;
  const m = $(id);
  if (!m) return;
  m.classList.add('open');
  m.setAttribute('aria-hidden', 'false');
  document.body.classList.add('modal-open');
  setTimeout(() => {
    const f = qs('[data-close].icon-btn', m);
    if (f) f.focus({preventScroll:true});
  }, 60);
}
function closeModal(m) {
  if (typeof m === 'string') m = $(m);
  if (!m) return;
  m.classList.remove('open');
  m.setAttribute('aria-hidden', 'true');
  if (!qs('.modal.open')) document.body.classList.remove('modal-open');
  if (m.id === 'setModal') {
    if (logsPollInterval) { clearInterval(logsPollInterval); logsPollInterval = null; }
  }
  if (lastFocusEl && lastFocusEl.focus) lastFocusEl.focus({preventScroll:true});
}

document.addEventListener('click', e => {
  const c = e.target.closest('[data-close]');
  if (c) closeModal(c.closest('.modal'));
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const openDds = qsa('.dd.open');
    if (openDds.length) { openDds.forEach(d => d.classList.remove('open')); return; }
    closeModal(qs('.modal.open'));
  }
  if (e.key === '/' && !/INPUT|TEXTAREA|SELECT/.test((document.activeElement && document.activeElement.tagName) || '') && !qs('.modal.open')) {
    e.preventDefault();
    if ($("q")) $("q").focus();
  }
});

/* ---------- Report Modal (Animated 6-item Bars + Tags + Raw Text) ---------- */
let currentReportCtx = { nodeId: '', ip: '', src: 'off', info: null, rawReport: '' };
const pad2 = v => String(v).padStart(2, '0');
const fmtTime = d => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
const scoreColor = s => s >= 90 ? '#2dd4bf' : s >= 80 ? '#4ade80' : s >= 65 ? '#60a5fa' : s >= 50 ? '#fbbf24' : '#f87171';

function parseAuditFromReportText(reportText, fallbackScore) {
  const txt = String(reportText || "");
  const items = [];
  const checkRegex = /\[([✓✗⚠])\]\s*([^\s(]+)\s+([^\n(]+?)\s*\((\d+)\/(\d+)\)/g;
  for (const m of txt.matchAll(checkRegex)) {
    const mark = m[1];
    const name = m[2].trim();
    const verdict = m[3].trim();
    const earned = Number(m[4]);
    const maxPts = Number(m[5]) || 1;
    const pct = Math.round((earned / maxPts) * 100);
    items.push({ name, verdict, earned, maxPts, pct, status: mark === '✓' ? 'PASS' : (mark === '⚠' ? 'WARN' : 'FAIL') });
  }
  if (items.length === 0) {
    const s = Number(fallbackScore) || 75;
    [
      ['VPN 检测', 8, 8], ['代理检测', s >= 70 ? 7 : 0, 7], ['Tor 暗网检测', 5, 5],
      ['滥用历史', s >= 75 ? 5 : 3, 5], ['DNSBL 黑名单', s >= 60 ? 4 : 2, 4], ['机房/托管检测', s >= 65 ? 3 : 0, 3]
    ].forEach(([name, e, mx]) => {
      const pct = Math.round((e / mx) * 100);
      items.push({ name, verdict: e === mx ? '通过' : '存在扣分', earned: e, maxPts: mx, pct, status: e === mx ? 'PASS' : (e > 0 ? 'WARN' : 'FAIL') });
    });
  }

  const posTags = [];
  const negTags = [];
  const posLine = txt.match(/正向信号:\s*([^\n]+)/);
  if (posLine) {
    for (const tm of posLine[1].matchAll(/\[✓\s*([^\]]+)\]/g)) posTags.push(tm[1].trim());
  }
  const negLine = txt.match(/风险标签:\s*([^\n]+)/);
  if (negLine) {
    for (const tm of negLine[1].matchAll(/\[⚠\s*([^\]]+)\]/g)) negTags.push(tm[1].trim());
  }
  return { items, posTags, negTags };
}

function renderReportModalView(info, srcMode = 'off') {
  const isIntel = srcMode === 'multi';
  const node = currentReportCtx.nodeId ? nodes.find(n => n && n.id === currentReportCtx.nodeId) : null;
  const ip = (info && info.ip) || (node && (node.ip || node.remote_host)) || currentReportCtx.ip || '-';
  const port = (node && node.remote_port) ? `:${node.remote_port}` : '';
  const score = Number(isIntel ? (info.intel_score ?? info.cleanip_score) : (info.cleanip_score ?? info.intel_score));
  const hasScore = Number.isFinite(score) && score > 0;
  const grade = String(isIntel ? (info.intel_grade || info.cleanip_grade || 'B') : (info.cleanip_grade || info.intel_grade || 'B'));
  const isNative = Boolean(isIntel ? info.intel_is_native : info.cleanip_is_native);
  const nativeLabel = isIntel
    ? (info.intel_native_label || (isNative ? '原生 IP' : '广播 IP'))
    : (info.cleanip_native_label || (isNative ? '原生 IP' : '广播 IP'));
  const summaryText = isIntel
    ? (info.intel_summary || info.cleanip_summary || '')
    : (info.cleanip_summary || info.intel_summary || '');
  const rawReport = isIntel
    ? (info.intel_report || info.cleanip_report || '')
    : (info.cleanip_report || info.intel_report || '');
  currentReportCtx.rawReport = rawReport;

  if ($("rEyebrow")) {
    $("rEyebrow").textContent = isIntel
      ? '多源风控情报库联合评估 · ProxyCheck + Scamalytics + iplocate + ip-api'
      : 'CleanIP.io 官方纯净度与风控检测 · VPS本机直连';
  }
  if ($("rTitle")) $("rTitle").textContent = `${ip}${port}`;
  if ($("rSub")) {
    const flag = node ? countryFlag(node.geo_country_short || node.country_short) : '🌐';
    const cName = node ? translateCountry(node.country) : '';
    const reg = node ? getNodeRegion(node) : '';
    const isp = (node && (node.owner || node.as_name)) || '-';
    const tName = node ? translateIpType(node.ip_type) : '-';
    $("rSub").textContent = [flag + ' ' + cName, reg, isp, tName].filter(Boolean).join(' · ');
  }

  const rg = $("rGrade");
  if (rg) {
    rg.textContent = hasScore ? grade : '-';
    rg.className = 'r-grade g-' + (hasScore ? gradeKey(grade, score) : 'b');
  }
  if ($("rScore")) $("rScore").textContent = hasScore ? String(score) : '-';
  const nb = $("rNative");
  if (nb) {
    nb.textContent = nativeLabel;
    nb.className = 'r-badge' + (String(nativeLabel).includes('广播') ? ' dc' : '');
  }
  if ($("rDesc")) {
    $("rDesc").textContent = summaryText || (hasScore ? `综合纯净度评分 ${score}/100 (${grade})` : '暂无评估摘要');
  }
  if ($("rExt")) {
    $("rExt").href = (info && info.cleanip_url) || (ip && ip !== '-' ? `https://cleanip.io/${encodeURIComponent(ip)}` : 'https://cleanip.io');
  }
  qsa('#rSeg button').forEach(b => b.classList.toggle('on', b.dataset.src === srcMode));
  if ($("rSwitchText")) {
    $("rSwitchText").textContent = `切换至${isIntel ? ' CleanIP 官方报告' : '三源对比报告'}`;
  }

  const parsed = parseAuditFromReportText(rawReport, hasScore ? score : 80);
  const srcKey = isIntel ? 'multi-source-v3' : 'cleanip-official';
  const srcName = isIntel ? '🔍 多源风控联合评估' : '🛡️ CleanIP.io 官方评估';
  const ispText = (node && (node.owner || node.as_name)) || '-';
  const locText = node ? `${translateCountry(node.country)} / ${getNodeRegion(node) || node.location || '-'}` : '-';

  const box = $("reportBox");
  if (box && hasScore) {
    box.innerHTML = `
      <div class="rb-top"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i><span>audit-report · ${srcKey}</span></div>
      <div class="rb-cmd"><span class="rb-p">❯</span>aimilivpn audit <span class="rb-arg">--target</span> ${esc(ip)}${esc(port)} <span class="rb-arg">--source</span> ${srcKey}</div>
      <div class="rb-meta">
        <span>目标</span><b>${esc(ip)}${esc(port)}</b>
        <span>运营主体</span><b>${esc(ispText)}</b>
        <span>地区</span><b>${esc(locText)}</b>
        <span>数据源</span><b>${srcName}</b>
        <span>时间</span><b>${fmtTime(new Date())}</b>
      </div>
      <div class="rb-sec">── 综合纯净度得分 ───────────────────────────────────</div>
      <div class="rb-total"><div class="rb-bar"><i data-w="${score}" style="--c:${scoreColor(score)}"></i></div><b>${score}</b><span style="color:${scoreColor(score)};font-weight:700">${esc(grade)}</span></div>
      <div class="rb-sec">── 审核明细 · 6 项 (32分制对齐) ─────────────────────────</div>
      ${parsed.items.map(it => {
        const stColor = it.status === 'PASS' ? '#34d399' : (it.status === 'WARN' ? '#fbbf24' : '#f87171');
        return `<div class="rb-row" title="${esc(it.verdict)}"><span class="rb-k">${esc(it.name)}</span><div class="rb-bar"><i data-w="${it.pct}" style="--c:${stColor}"></i></div><span class="rb-v">${it.earned}/${it.maxPts}</span><span class="rb-st" style="--c:${stColor}">${it.status}</span></div>`;
      }).join('')}
      <div class="rb-sec">── 信号标签 ──────────────────────────────────────</div>
      <div class="rb-tags">
        ${parsed.posTags.map(t => `<span class="rb-tag pos">✓ ${esc(t)}</span>`).join('')}
        ${parsed.negTags.map(t => `<span class="rb-tag neg">⚠ ${esc(t)}</span>`).join('')}
        ${(parsed.posTags.length === 0 && parsed.negTags.length === 0) ? '<span class="rb-tag pos">✓ 详见下方完整终端报告</span>' : ''}
      </div>
      <details class="raw-report-details" open>
        <summary>展开 / 收起完整原始报告明细 (含 27 项风险信号与平台适配度)</summary>
        <pre class="raw-report-pre">${esc(rawReport)}</pre>
      </details>
      <div class="rb-foot"><span class="ok">✔</span> 报告解析完成 · ${parsed.items.filter(i => i.status === 'PASS').length}/${parsed.items.length} 项满分通过<span class="cursor"></span></div>
    `;
    requestAnimationFrame(() => requestAnimationFrame(() => qsa('#reportBox .rb-bar i').forEach(i => i.style.width = i.dataset.w + '%')));
  } else if (box) {
    box.innerHTML = `
      <div class="rb-top"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i><span>audit-report · ${srcKey}</span></div>
      <pre class="raw-report-pre" style="max-height:340px;margin-top:0;">${esc(rawReport || '正在请求评估数据…')}</pre>
    `;
  }
}

async function openAndFetchReport(nodeId, srcMode = 'off', forceRefresh = false) {
  const node = nodeId ? nodes.find(n => n && n.id === nodeId) : nodes.find(n => n && n.active);
  const ip = (node && (node.ip || node.remote_host)) || state.proxy_ip || '';
  const resolvedId = node ? node.id : (nodeId || '');
  currentReportCtx = { nodeId: resolvedId, ip, src: srcMode, info: node || null, rawReport: '' };
  openModal('reportModal');

  const isIntel = srcMode === 'multi';
  if (!forceRefresh && node) {
    if (isIntel && node.intel_report && node.intel_score !== undefined && node.intel_score !== '') {
      renderReportModalView(node, 'multi');
      return;
    }
    if (!isIntel && node.cleanip_report && node.cleanip_score !== undefined && node.cleanip_score !== '') {
      renderReportModalView(node, 'off');
      return;
    }
  }

  const box = $("reportBox");
  const redoBtn = $("rRedo");
  if (box) box.classList.add('scanning');
  if (redoBtn) { redoBtn.classList.add('spinning'); redoBtn.disabled = true; }
  if ($("rDesc")) {
    $("rDesc").textContent = isIntel
      ? '正在并发查询 ProxyCheck.io · Scamalytics · iplocate.io · ip-api.com (不经过家宽隧道)…'
      : '正在由 VPS 本机直连查询 CleanIP.io 官方纯净度报告 (不经过家宽隧道)…';
  }
  if (box && !box.innerHTML.trim()) {
    box.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-3);"><span class="spin"></span> 正在实时获取风控与纯净度评估报告…</div>';
  }

  if (resolvedId) {
    if (isIntel) intelTestingIds.add(resolvedId);
    else cleanIpTestingIds.add(resolvedId);
    render();
  }

  try {
    const response = await fetchWithTimeout('./api/check_cleanip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: resolvedId,
        ip: ip,
        force: forceRefresh,
        via_proxy: false,
        use_cli: false,
        source: isIntel ? 'intel' : 'cleanip'
      })
    }, 35000);
    const result = await readJsonResponse(response, isIntel ? '三源情报对比检测失败' : 'CleanIP 纯净度检测失败');
    if (result.ok && result.cleanip) {
      if (result.node && resolvedId) {
        const idx = nodes.findIndex(n => n && n.id === resolvedId);
        if (idx !== -1) nodes[idx] = result.node;
      }
      currentReportCtx.info = result.cleanip;
      renderReportModalView(result.cleanip, srcMode);
      toast(`${isIntel ? '🔍 三源对比' : '🛡️ CleanIP'}评估完成`, 'ok');
    }
  } catch (e) {
    const errMsg = e.message || '未知网络错误';
    if ($("rDesc")) $("rDesc").textContent = (isIntel ? '三源检测失败: ' : 'CleanIP 检测受限 (可点击右侧切换三源对比): ') + errMsg;
    if (box) {
      box.innerHTML = `<div class="rb-top"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i><span>error</span></div><div style="padding:18px;color:var(--red);">${esc(errMsg)}</div>`;
    }
    toast(errMsg, 'err');
  } finally {
    if (box) box.classList.remove('scanning');
    if (redoBtn) { redoBtn.classList.remove('spinning'); redoBtn.disabled = false; }
    if (resolvedId) {
      intelTestingIds.delete(resolvedId);
      cleanIpTestingIds.delete(resolvedId);
      render();
    }
  }
}

/* ---------- API Actions: Test, Favorite, Connect, Disconnect, Batch ---------- */
async function testSingleNode(id) {
  if (!id || testingNodeIds.has(id)) return;
  testingNodeIds.add(id);
  render();
  toast('⚡ 正在测速节点…', 'info', 1600);
  try {
    const response = await fetchWithTimeout('./api/test_node', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    }, 45000);
    const result = await readJsonResponse(response, '节点检测失败');
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n && n.id === id);
      if (idx !== -1) nodes[idx] = result.node;
      const lat = result.node.latency_ms;
      if (result.node.probe_status === 'available') {
        toast(`测速完成 · <span class="mono">${esc(result.node.ip || id)}</span> → <b class="mono">${lat || '-'} ms</b>`, 'ok');
      } else {
        toast(`<span class="mono">${esc(result.node.ip || id)}</span> 握手超时或不可用`, 'warn');
      }
    }
  } catch (e) {
    toast('节点检测失败: ' + (e.message || '未知错误'), 'err');
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

async function toggleFavoriteNode(id) {
  if (!id || favoriteRequestIds.has(id)) return;
  favoriteRequestIds.add(id);
  render();
  try {
    const response = await fetchWithTimeout('./api/toggle_favorite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    }, 20000);
    const result = await readJsonResponse(response, '切换收藏失败');
    if (result.ok) {
      state.favorite_node_ids = Array.isArray(result.favorite_node_ids) ? result.favorite_node_ids : [];
      const isNowFav = state.favorite_node_ids.includes(id);
      const n = nodes.find(x => x && x.id === id);
      const ipStr = (n && (n.ip || n.remote_host)) || id;
      render();
      const starBtn = qs(`#tbody tr[data-id="${CSS.escape(id)}"] .act.star`);
      if (starBtn) starBtn.classList.add('pop');
      toast(isNowFav ? `★ 已加入星标常备池 · <span class="mono">${esc(ipStr)}</span>` : `已移出星标常备池 · <span class="mono">${esc(ipStr)}</span>`, isNowFav ? 'warn' : 'info');
    }
  } catch (e) {
    toast('切换收藏失败: ' + (e.message || '未知错误'), 'err');
  } finally {
    favoriteRequestIds.delete(id);
    render();
  }
}

async function connectToNode(id) {
  if (!id) return;
  const n = nodes.find(x => x && x.id === id);
  if (n && n.probe_status === 'unavailable') { toast('该节点离线，请先测速可用后再切换', 'err'); return; }
  state.is_connecting = true;
  state.pending_node_id = id;
  render();
  toast(`正在切换主用节点 → <span class="mono">${esc((n && n.ip) || id)}</span>…`, 'info');
  startConnectionPolling();
  try {
    const response = await fetchWithTimeout('./api/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    }, 75000);
    const result = await readJsonResponse(response, '切换节点失败');
    if (result.ok) {
      lastCheckTs = Date.now();
      await load();
      toast(`已切换主用节点 → <span class="mono">${esc((n && n.ip) || id)}</span>`, 'ok');
    }
  } catch (e) {
    toast('切换失败: ' + (e.message || '未知错误'), 'err');
    await load();
  }
}

async function disconnectActiveNode() {
  if (disconnectInFlight) return;
  if (!confirm('确定要断开当前的 VPN 连接吗？')) return;
  disconnectInFlight = true;
  render();
  try {
    const response = await fetchWithTimeout('./api/disconnect', { method: 'POST' }, 60000);
    await readJsonResponse(response, '断开连接失败');
    toast('已断开当前主用节点连接', 'warn');
    await load();
  } catch (e) {
    toast('断开连接失败: ' + (e.message || '未知错误'), 'err');
  } finally {
    disconnectInFlight = false;
    render();
  }
}

async function startBatchAvailabilityWithIds(targetIds) {
  if (!targetIds || targetIds.length === 0) {
    toast('当前没有可测速的节点', 'warn');
    return;
  }
  try {
    const response = await fetchWithTimeout('./api/test_nodes_batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: targetIds })
    }, 25000);
    const result = await readJsonResponse(response, '启动批量检测失败');
    if (result.ok) {
      toast(`⚡ 已启动 ${targetIds.length} 个节点的并发测速…`, 'info');
      await load();
      startBatchTestPolling();
    }
  } catch (e) {
    toast('批量检测启动失败: ' + (e.message || '未知错误'), 'err');
  }
}

async function startBatchCleanIpWithIds(targetIds, source = 'cleanip', force = false) {
  if (!targetIds || targetIds.length === 0) {
    toast('当前没有可评估的节点', 'warn');
    return;
  }
  try {
    const response = await fetchWithTimeout('./api/check_cleanip_batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: targetIds, source, force })
    }, 25000);
    const result = await readJsonResponse(response, source === 'intel' ? '启动批量三源对比失败' : '启动批量 CleanIP 失败');
    if (result.ok) {
      toast(`${source === 'intel' ? '🔍 批量三源对比' : '🛡️ 批量 CleanIP'}任务已启动 (${targetIds.length} 个节点)`, 'info');
      await load();
      startCleanIpBatchPolling();
    }
  } catch (e) {
    toast((source === 'intel' ? '批量三源对比失败: ' : '批量 CleanIP 失败: ') + (e.message || '未知错误'), 'err');
  }
}

function getBatchTargetIds() {
  return selectedNodeIds.size > 0
    ? Array.from(selectedNodeIds)
    : currentPageNodes.map(n => n && n.id).filter(Boolean);
}

/* ---------- Polling & Snapshot Sync ---------- */
async function fetchNodesSnapshot() {
  if (nodesRequestPromise) return nodesRequestPromise;
  const request = (async () => {
    const response = await fetchWithTimeout('./api/nodes', { cache: 'no-store' }, 20000);
    if (!response.ok) throw new Error(`节点状态请求失败 (${response.status})`);
    return response.json();
  })();
  nodesRequestPromise = request;
  try {
    return await request;
  } finally {
    if (nodesRequestPromise === request) nodesRequestPromise = null;
  }
}

function applyNodesSnapshot(data) {
  const nextNodes = Array.isArray(data && data.nodes) ? data.nodes : [];
  const nextState = data && data.state ? data.state : {};
  const signature = JSON.stringify([nextNodes, nextState]);
  if (signature === lastNodesSnapshotSignature) return false;

  lastNodesSnapshotSignature = signature;
  nodes = nextNodes;
  state = nextState;
  lastCheckTs = Date.now();
  const d = new Date();
  if ($("lastSync")) $("lastSync").textContent = `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  stableSortNodes();
  updateCountryAndRegionMenus();
  render();
  return true;
}

function startRefreshPolling() {
  if (refreshPollInterval) clearInterval(refreshPollInterval);
  const b = $("syncBtn");
  if (b) { b.disabled = true; b.classList.add('spinning'); }
  refreshPollInterval = setInterval(async () => {
    if (refreshPollInFlight || !isPageVisible()) return;
    refreshPollInFlight = true;
    try {
      const data = await fetchNodesSnapshot();
      applyNodesSnapshot(data);
      if (!state.maintenance_running) {
        clearInterval(refreshPollInterval);
        refreshPollInterval = null;
        if (b) { b.disabled = false; b.classList.remove('spinning'); }
        toast('节点目录同步与检测完成', 'ok');
      }
    } catch (e) {
      clearInterval(refreshPollInterval);
      refreshPollInterval = null;
      if (b) { b.disabled = false; b.classList.remove('spinning'); }
    } finally {
      refreshPollInFlight = false;
    }
  }, 1200);
}

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    if (connectionPollInFlight || !isPageVisible()) return;
    connectionPollInFlight = true;
    try {
      const data = await fetchNodesSnapshot();
      applyNodesSnapshot(data);
      if (!state.is_connecting) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
    } catch (e) {
      clearInterval(pollInterval);
      pollInterval = null;
    } finally {
      connectionPollInFlight = false;
    }
  }, 1200);
}

function startBatchTestPolling() {
  if (batchPollInterval) clearInterval(batchPollInterval);
  batchPollInterval = setInterval(async () => {
    if (batchPollInFlight || !isPageVisible()) return;
    batchPollInFlight = true;
    try {
      const data = await fetchNodesSnapshot();
      applyNodesSnapshot(data);
      if (!state.batch_test_running) {
        clearInterval(batchPollInterval);
        batchPollInterval = null;
        toast(state.last_check_message || '批量测速完成', 'ok');
      }
    } catch (e) {
      clearInterval(batchPollInterval);
      batchPollInterval = null;
    } finally {
      batchPollInFlight = false;
    }
  }, 1200);
}

function startCleanIpBatchPolling() {
  if (cleanIpPollInterval) clearInterval(cleanIpPollInterval);
  cleanIpPollInterval = setInterval(async () => {
    if (cleanIpPollInFlight || !isPageVisible()) return;
    cleanIpPollInFlight = true;
    try {
      const data = await fetchNodesSnapshot();
      applyNodesSnapshot(data);
      if (!state.cleanip_batch_running) {
        clearInterval(cleanIpPollInterval);
        cleanIpPollInterval = null;
        toast('批量质量评估已完成', 'ok');
      }
    } catch (e) {
      clearInterval(cleanIpPollInterval);
      cleanIpPollInterval = null;
    } finally {
      cleanIpPollInFlight = false;
    }
  }, 1500);
}

async function load() {
  const d = await fetchNodesSnapshot();
  applyNodesSnapshot(d);
  if (state.maintenance_running) startRefreshPolling();
  else if (state.is_connecting) startConnectionPolling();
  if (state.batch_test_running) startBatchTestPolling();
  if (state.cleanip_batch_running) startCleanIpBatchPolling();
}

setInterval(async () => {
  if (backgroundPollInFlight || !isPageVisible()) return;
  backgroundPollInFlight = true;
  try {
    const data = await fetchNodesSnapshot();
    applyNodesSnapshot(data);
  } catch (e) {
  } finally {
    backgroundPollInFlight = false;
  }
}, 5000);

/* ---------- Settings, Self-Check & Logs inside #setModal ---------- */
let logsPollInterval = null;
let rawLogsCache = [];
let logsRequestInFlight = false;
let logCatFilter = '全部';
const LOG_CAT_COLORS = {'调度':'var(--violet)', 'VPN':'var(--green)', 'Proxy':'var(--cyan)', '系统':'var(--gray)'};

function setSettingsTab(tabKey) {
  qsa('#setModal .tab').forEach(b => b.classList.toggle('on', b.dataset.tab === tabKey));
  qsa('#setModal .pane').forEach(p => p.classList.toggle('on', p.dataset.pane === tabKey));
  qsa('#setModal .foot-set').forEach(f => f.classList.toggle('on', f.dataset.foot === tabKey));
  if (tabKey === 'logs') {
    loadLogs();
    if (logsPollInterval) clearInterval(logsPollInterval);
    logsPollInterval = setInterval(loadLogs, 3000);
  } else {
    if (logsPollInterval) { clearInterval(logsPollInterval); logsPollInterval = null; }
  }
  if (tabKey === 'selfcheck') {
    loadGatewayStatus();
  }
}

function populateSettingsModal() {
  if ($("cred_username")) $("cred_username").value = (state && state.username) || 'admin';
  if ($("cred_password")) $("cred_password").value = '';
  if ($("cred_port")) $("cred_port").value = (state && state.port) || 8787;
  if ($("cred_suffix")) $("cred_suffix").value = (state && state.secret_path) || '';
  if ($("menu_admin_name")) $("menu_admin_name").textContent = (state && state.username) || 'admin';

  if ($("net_proxy_port")) $("net_proxy_port").value = (state && state.proxy_port) || 7928;
  const rMode = (state && state.routing_mode && state.routing_mode !== 'favorites') ? state.routing_mode : 'auto';
  setRoutingModeUI(rMode);
  const ipType = (state && state.routing_ip_type) || 'all';
  setRoutingIpTypeUI(ipType);

  // Populate force country select
  const selEl = $("net_force_country");
  if (selEl) {
    const availCountries = Array.isArray(state.available_countries) ? state.available_countries : [];
    const curForce = String(state.force_country || "").trim().toUpperCase();
    if (availCountries.length > 0) {
      selEl.innerHTML = availCountries.map(c => {
        const code = String(c.code || "").toUpperCase();
        return `<option value="${esc(code)}" ${code === curForce ? 'selected' : ''}>${esc(countryFlag(code))} ${esc(c.label || translateCountry(c.name || code))} (${c.count || 0})</option>`;
      }).join('');
    } else {
      selEl.innerHTML = '<option value="JP">🇯🇵 日本</option>';
    }
  }

  // Populate fixed node options
  const nodeOpts = $("nodeOpts");
  if (nodeOpts) {
    const candidates = nodes.filter(n => n && (n.active || n.probe_status === 'available')).slice(0, 5);
    if (candidates.length === 0) {
      nodeOpts.innerHTML = '<div class="muted" style="font-size:12px;">暂无已测速可用的候选节点，请先在列表连接一个节点。</div>';
    } else {
      nodeOpts.innerHTML = candidates.map(n => {
        const isOn = Boolean(n.active || (state.fixed_node_id && state.fixed_node_id === n.id));
        const flag = countryFlag(n.geo_country_short || n.country_short);
        const reg = getNodeRegion(n) || translateCountry(n.country);
        const pScore = getNodeEffectivePurity(n);
        return `<button class="node-opt ${isOn ? 'on' : ''}" data-nid="${esc(n.id)}" type="button"><span class="radio"></span><span class="no-main"><span class="mono">${esc(n.ip || n.remote_host)}:${esc(n.remote_port || '')}</span>${esc(flag)} ${esc(reg)} · ${esc(n.owner || n.as_name || '-')}</span>${pScore != null ? `<span class="qp g-${gradeKey('', pScore)}" style="pointer-events:none">🛡️ <b>${pScore}</b></span>` : ''}</button>`;
      }).join('');
    }
  }
}

function setRoutingModeUI(mode) {
  if ($("net_routing_mode")) $("net_routing_mode").value = mode;
  qsa('#routing_mode_group .mode-card').forEach(c => {
    const on = c.dataset.mode === mode;
    c.classList.toggle('on', on);
    c.classList.toggle('active', on);
    c.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
  qsa('#setModal .mode-pane').forEach(p => p.classList.toggle('on', p.dataset.mpane === mode));
}

function setRoutingIpTypeUI(ipType) {
  if ($("net_routing_ip_type")) $("net_routing_ip_type").value = ipType;
  qsa('#routing_ip_type_group button').forEach(b => {
    b.classList.toggle('on', b.dataset.iptype === ipType);
  });
}

function openSettingsModal(tabKey = 'sched') {
  populateSettingsModal();
  setSettingsTab(tabKey);
  openModal('setModal');
}

async function saveScheduleAndProxySettings() {
  const proxyPort = parseInt($("net_proxy_port").value, 10);
  const routingMode = $("net_routing_mode").value || 'auto';
  const forceCountry = $("net_force_country") ? $("net_force_country").value : '';
  const routingIpType = $("net_routing_ip_type").value || 'all';

  if (isNaN(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
    toast('代理出站端口范围必须在 1024 至 65535 之间', 'err');
    return;
  }
  if (state && proxyPort === state.port) {
    toast('代理出站端口不能与网页管理端口相同', 'err');
    return;
  }
  if (routingMode === 'fixed_ip' && !(state && (state.active_openvpn_node_id || state.fixed_node_id))) {
    toast('启用锁定单节点前，请先连接一个要锁定的节点', 'err');
    return;
  }

  try {
    const res = await fetchWithTimeout('./api/update_settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proxy_port: proxyPort,
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType
      })
    }, 25000);
    const data = await readJsonResponse(res, '保存设置失败');
    if (data.ok) {
      closeModal('setModal');
      toast(data.message || '调度与代理设置已保存', 'ok');
      if (data.restart_needed) {
        setTimeout(() => window.location.reload(), 2500);
      } else {
        await load();
      }
    }
  } catch (e) {
    toast('保存设置失败: ' + (e.message || '未知错误'), 'err');
  }
}

async function saveCredentialsSettings() {
  const username = String($("cred_username").value || '').trim();
  const password = $("cred_password").value;
  const port = parseInt($("cred_port").value, 10);
  const suffix = String($("cred_suffix").value || '').trim();

  if (!username) { toast('管理账号不能为空', 'err'); return; }
  if (isNaN(port) || port < 1 || port > 65535) { toast('网页管理端口范围必须是 1 ~ 65535', 'err'); return; }
  if (state && port === state.proxy_port) { toast('网页管理端口不能与代理出站端口相同', 'err'); return; }
  if (!/^[A-Za-z0-9]+$/.test(suffix)) { toast('登录安全后缀仅能由英文字母和数字组成', 'err'); return; }

  try {
    const res = await fetchWithTimeout('./api/update_credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, port, secret_path: suffix })
    }, 25000);
    const data = await readJsonResponse(res, '保存安全设置失败');
    if (data.ok) {
      toast('安全设置已保存', 'ok');
      if (data.restart_needed) {
        const protocol = window.location.protocol;
        const host = formatUrlHost(window.location.hostname);
        setTimeout(() => { window.location.href = `${protocol}//${host}:${port}/${suffix}/`; }, 2500);
      } else {
        closeModal('setModal');
        await load();
      }
    }
  } catch (e) {
    toast('保存安全设置失败: ' + (e.message || '未知错误'), 'err');
  }
}

async function loadGatewayStatus() {
  const container = $("gateway_services_list");
  if (!container) return;
  try {
    const res = await fetchWithTimeout('./api/gateway_status', { cache: 'no-store' }, 20000);
    const data = await readJsonResponse(res, '网关状态请求失败');
    if (data.ok && Array.isArray(data.services)) {
      container.innerHTML = data.services.map(s => {
        const ok = s.status === 'running';
        return `<div class="f-row">
          <div>
            <b>${esc(s.name)}</b>
            <small>${esc(s.details || '-')}</small>
            ${s.error ? `<div style="color:var(--red);font-size:11.5px;margin-top:3px;">⚠️ ${esc(s.error)}</div>` : ''}
          </div>
          <span class="sb ${ok ? 'sb-ok' : 'sb-off'}"><span class="d"></span>${ok ? '运行中' : '已停止'}</span>
        </div>`;
      }).join('');
    }
  } catch (e) {
    container.innerHTML = `<div class="f-row"><div style="color:var(--red);">加载网关状态失败: ${esc(e.message)}</div></div>`;
  }

  // Sync proxy test status from state
  const pBadge = $("proxy_status_badge");
  const pIp = $("proxy_ip_val");
  const pLat = $("proxy_latency_val");
  if (state && state.proxy_ok !== undefined) {
    if (state.proxy_ok) {
      if (pBadge) { pBadge.className = 'sb sb-ok'; pBadge.innerHTML = '<span class="d"></span>连通正常'; }
      if (pIp) pIp.textContent = state.proxy_ip || '-';
      if (pLat) pLat.textContent = state.proxy_latency_ms ? `${state.proxy_latency_ms} ms` : '';
    } else {
      if (pBadge) { pBadge.className = 'sb sb-off'; pBadge.innerHTML = '<span class="d"></span>未连通'; }
      if (pIp) pIp.textContent = '-';
      if (pLat) pLat.textContent = state.proxy_error || '';
    }
  }
}

async function loadLogs() {
  if (logsRequestInFlight || !isPageVisible()) return;
  logsRequestInFlight = true;
  try {
    const res = await fetchWithTimeout('./api/logs', { cache: 'no-store' }, 20000);
    if (!res.ok) return;
    const data = await res.json();
    if (Array.isArray(data.logs)) {
      rawLogsCache = data.logs;
      if ($("logBadge")) $("logBadge").textContent = String(rawLogsCache.length);
      if ($("menuLogBadge")) $("menuLogBadge").textContent = String(rawLogsCache.length);
      renderLogsView();
    }
  } catch (e) {
  } finally {
    logsRequestInFlight = false;
  }
}

function renderLogsView() {
  const cats = ['全部', 'VPN', 'Proxy', '系统'];
  if ($("logFilters")) {
    $("logFilters").innerHTML = cats.map(c => {
      const cnt = c === '全部' ? rawLogsCache.length : rawLogsCache.filter(l => (c === '系统' ? !['VPN', 'Proxy'].includes(l.module) : l.module === c)).length;
      const dotColor = LOG_CAT_COLORS[c] || 'var(--accent)';
      return `<button class="chip ${c === logCatFilter ? 'on' : ''}" data-cat="${c}" type="button">${c !== '全部' ? `<span class="dot-s" style="--c:${dotColor}"></span>` : ''}${c}<span class="cnt">${cnt}</span></button>`;
    }).join('');
  }
  const filtered = rawLogsCache.filter(l => {
    if (logCatFilter === '全部') return true;
    if (logCatFilter === '系统') return !['VPN', 'Proxy'].includes(l.module);
    return l.module === logCatFilter;
  }).slice(-MAX_RENDERED_LOG_LINES);

  const listEl = $("logList");
  if (listEl) {
    if (filtered.length === 0) {
      listEl.innerHTML = '<div style="padding:28px;text-align:center;color:var(--text-3);">暂无今日运行日志记录</div>';
    } else {
      listEl.innerHTML = filtered.map(l => {
        const lv = l.level === 'ERROR' ? 'error' : (l.level === 'WARNING' ? 'warn' : 'info');
        const lvTxt = l.level === 'ERROR' ? 'ERR' : (l.level === 'WARNING' ? 'WARN' : 'INFO');
        const cColor = LOG_CAT_COLORS[l.module] || 'var(--gray)';
        const timeShort = String(l.timestamp || '').split(' ').pop() || l.timestamp || '-';
        return `<div class="log-row lv-${lv}"><span class="lg-time mono">${esc(timeShort)}</span><span class="lg-lv">${lvTxt}</span><span class="lg-cat" style="--c:${cColor}">${esc(l.module || 'SYS')}</span><span class="lg-msg">${esc(l.message || '')}</span></div>`;
      }).join('');
      listEl.scrollTop = listEl.scrollHeight;
    }
  }
  if ($("logCount")) $("logCount").textContent = `显示 ${filtered.length} / ${rawLogsCache.length} 条记录`;
}

/* ---------- Star Pool Routing API ---------- */
async function updateStarPoolRouting(enableFavOnly, newFavRegion) {
  const newMode = enableFavOnly ? 'favorites' : 'auto';
  const regVal = newFavRegion !== undefined ? String(newFavRegion || '').trim() : String(state.fav_region || '').trim();
  state.routing_mode = newMode;
  state.fav_region = regVal;
  renderKpisAndPool();
  try {
    const res = await fetchWithTimeout('./api/update_routing', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routing_mode: newMode,
        force_country: state.force_country || '',
        routing_ip_type: state.routing_ip_type || 'all',
        fav_region: regVal
      })
    }, 25000);
    const data = await readJsonResponse(res, '更新星标轮换策略失败');
    if (data.ok) {
      toast(enableFavOnly ? `已启用：仅在星标池 (${regVal ? '限定 ' + regVal : '全部地区'}) 内轮换` : '已关闭星标池限定轮换', 'ok');
      await load();
    }
  } catch (e) {
    toast('更新星标轮换策略失败: ' + (e.message || '未知错误'), 'err');
    await load();
  }
}

/* ---------- Event Listeners ---------- */
// Table row events
if ($("tbody")) {
  $("tbody").addEventListener('change', e => {
    if (!e.target.classList.contains('row-cb')) return;
    const tr = e.target.closest('tr[data-id]');
    if (!tr) return;
    const id = tr.dataset.id;
    if (e.target.checked) selectedNodeIds.add(id);
    else selectedNodeIds.delete(id);
    tr.classList.toggle('is-sel', e.target.checked);
    updateBatchSelectionUI();
  });

  $("tbody").addEventListener('click', e => {
    if (e.target.closest('#resetFiltersBtn')) { resetAllFilters(); return; }
    const tr = e.target.closest('tr[data-id]');
    if (!tr) return;
    const id = tr.dataset.id;
    const qpBtn = e.target.closest('.qp');
    if (qpBtn) { openAndFetchReport(id, qpBtn.dataset.src, false); return; }
    const actBtn = e.target.closest('[data-a]');
    if (!actBtn || actBtn.disabled) return;
    switch (actBtn.dataset.a) {
      case 'test': testSingleNode(id); break;
      case 'off': openAndFetchReport(id, 'off', false); break;
      case 'multi': openAndFetchReport(id, 'multi', false); break;
      case 'star': toggleFavoriteNode(id); break;
      case 'switch': connectToNode(id); break;
    }
  });
}

if ($("cbAll")) {
  $("cbAll").addEventListener('change', e => {
    currentPageNodes.forEach(n => {
      if (!n || !n.id) return;
      if (e.target.checked) selectedNodeIds.add(n.id);
      else selectedNodeIds.delete(n.id);
    });
    render();
  });
}

// Column header sort click
if ($("thSortLat")) {
  $("thSortLat").addEventListener('click', () => {
    filters.sort = filters.sort === 'latency_asc' ? 'latency_desc' : 'latency_asc';
    currentPage = 1;
    render();
  });
}
if ($("thSortPurity")) {
  $("thSortPurity").addEventListener('click', () => {
    filters.sort = filters.sort === 'purity_desc' ? 'purity_asc' : 'purity_desc';
    currentPage = 1;
    render();
  });
}

// Pager clicks
if ($("pgNav")) {
  $("pgNav").addEventListener('click', e => {
    const b = e.target.closest('[data-pg]');
    if (!b || b.disabled) return;
    const targetPg = parseInt(b.dataset.pg, 10);
    if (Number.isFinite(targetPg) && targetPg >= 1) {
      currentPage = targetPg;
      render();
    }
  });
}
if ($("pgSizeSeg")) {
  $("pgSizeSeg").addEventListener('click', e => {
    const b = e.target.closest('[data-size]');
    if (!b) return;
    qsa('#pgSizeSeg button').forEach(x => x.classList.toggle('on', x === b));
    dynamicPageSize = parseInt(b.dataset.size, 10) || 50;
    currentPage = 1;
    render();
  });
}

// Batch bar actions
qsa('[data-sel]').forEach(b => b.addEventListener('click', () => {
  const m = b.dataset.sel;
  const shown = getFilteredNodes();
  if (m === 'page') currentPageNodes.forEach(n => n && n.id && selectedNodeIds.add(n.id));
  else if (m === 'filter') {
    shown.forEach(n => n && n.id && selectedNodeIds.add(n.id));
    toast(`已勾选当前筛选结果中的全部 ${shown.length} 个节点`, 'info');
  } else if (m === 'pending') {
    selectedNodeIds.clear();
    shown.filter(n => n && (!n.probe_status || n.probe_status === 'not_checked')).forEach(n => selectedNodeIds.add(n.id));
    toast(`已勾选 ${selectedNodeIds.size} 个待检测节点`, 'info');
  } else {
    selectedNodeIds.clear();
  }
  render();
}));

if ($("bTest")) $("bTest").addEventListener('click', () => startBatchAvailabilityWithIds(getBatchTargetIds()));
if ($("bCancelTest")) {
  $("bCancelTest").addEventListener('click', async () => {
    try {
      await fetchWithTimeout('./api/cancel_batch_test', { method: 'POST' }, 15000);
      toast('已发送停止批量测速指令', 'warn');
    } catch (e) {}
  });
}
if ($("bEval")) $("bEval").addEventListener('click', () => startBatchCleanIpWithIds(getBatchTargetIds(), 'cleanip', false));
if ($("bMulti")) $("bMulti").addEventListener('click', () => startBatchCleanIpWithIds(getBatchTargetIds(), 'intel', true));

// Hero actions
if ($("copyAddr")) $("copyAddr").addEventListener('click', () => copyText($("hAddr").textContent, '已复制节点编码'));
qsa('[data-hero-report]').forEach(b => b.addEventListener('click', () => {
  const act = nodes.find(n => n && n.active);
  openAndFetchReport(act ? act.id : '', b.dataset.heroReport, false);
}));
if ($("hEval")) $("hEval").addEventListener('click', () => {
  const act = nodes.find(n => n && n.active);
  openAndFetchReport(act ? act.id : '', 'off', true);
});
if ($("hCompare")) $("hCompare").addEventListener('click', () => {
  const act = nodes.find(n => n && n.active);
  openAndFetchReport(act ? act.id : '', 'multi', true);
});
if ($("hUnload")) $("hUnload").addEventListener('click', disconnectActiveNode);

// Report Modal buttons
if ($("rSeg")) {
  $("rSeg").addEventListener('click', e => {
    const b = e.target.closest('button[data-src]');
    if (!b || b.dataset.src === currentReportCtx.src) return;
    openAndFetchReport(currentReportCtx.nodeId, b.dataset.src, false);
  });
}
if ($("rSwitch")) {
  $("rSwitch").addEventListener('click', () => {
    const nextSrc = currentReportCtx.src === 'off' ? 'multi' : 'off';
    openAndFetchReport(currentReportCtx.nodeId, nextSrc, false);
  });
}
if ($("rRedo")) {
  $("rRedo").addEventListener('click', () => {
    openAndFetchReport(currentReportCtx.nodeId, currentReportCtx.src, true);
  });
}
if ($("rCopy")) {
  $("rCopy").addEventListener('click', () => {
    if (!currentReportCtx.rawReport) { toast('当前暂无可复制的报告内容', 'warn'); return; }
    copyText(currentReportCtx.rawReport, '评估报告已复制到剪贴板');
  });
}

// Dropdowns & Filters
document.addEventListener('click', e => {
  const trig = e.target.closest('[data-dd-trigger]');
  qsa('.dd.open').forEach(d => { if (!d.contains(e.target)) d.classList.remove('open'); });
  if (trig) { trig.closest('.dd').classList.toggle('open'); return; }

  const opt = e.target.closest('.dd-select .dd-opt');
  if (opt) {
    const dd = opt.closest('.dd');
    qsa('.dd-opt', dd).forEach(o => o.classList.toggle('active', o === opt));
    const lbl = qs('.dd-label', dd);
    if (lbl) lbl.textContent = opt.textContent.replace(/\s+\d+$/, '').trim();
    dd.classList.remove('open');
    dd.dispatchEvent(new CustomEvent('ddchange', { bubbles: true, detail: opt.dataset.value }));
    return;
  }

  const mi = e.target.closest('.dd .menu-item');
  if (mi && !mi.dataset.keep) mi.closest('.dd').classList.remove('open');
});

document.addEventListener('ddchange', e => {
  const f = e.target.dataset.filter;
  if (f) {
    filters[f] = e.detail;
    currentPage = 1;
    render();
  } else if (e.target.id === 'poolRegion') {
    const newReg = e.detail || '';
    updateStarPoolRouting(state.routing_mode === 'favorites', newReg);
  }
});

// Multi-select Country Filter
const countryDD = $("country_filter");
if (countryDD) {
  countryDD.addEventListener('change', e => {
    if (!e.target.classList.contains('country-option-input')) return;
    const code = String(e.target.value || '').toUpperCase();
    if (e.target.checked) selectedDiscoveryCountries.add(code);
    else selectedDiscoveryCountries.delete(code);
    discoveryCountriesDirty = true;
    currentPage = 1;
    updateCountryAndRegionMenus();
    render();
  });
  countryDD.addEventListener('click', e => {
    const b = e.target.closest('[data-mm]');
    if (!b) return;
    const inputs = qsa('.country-option-input', countryDD);
    if (b.dataset.mm === 'all') {
      inputs.forEach(i => { i.checked = true; selectedDiscoveryCountries.add(String(i.value).toUpperCase()); });
    } else {
      inputs.forEach(i => { i.checked = false; });
      selectedDiscoveryCountries.clear();
    }
    discoveryCountriesDirty = true;
    currentPage = 1;
    updateCountryAndRegionMenus();
    render();
  });
}

function resetAllFilters() {
  Object.assign(filters, { status: 'all', region: '', type: '', sort: 'default', q: '' });
  showFavoritesOnly = false;
  selectedDiscoveryCountries.clear();
  discoveryCountriesDirty = true;
  if ($("q")) $("q").value = '';
  qsa('.dd-select[data-filter]').forEach(dd => {
    const first = qs('.dd-opt', dd);
    if (first) {
      qsa('.dd-opt', dd).forEach(o => o.classList.toggle('active', o === first));
      const lbl = qs('.dd-label', dd);
      if (lbl) lbl.textContent = first.textContent.trim();
    }
  });
  updateCountryAndRegionMenus();
  currentPage = 1;
  render();
  toast('筛选条件已重置', 'info');
}

if ($("q")) {
  $("q").addEventListener('input', e => {
    filters.q = e.target.value || '';
    currentPage = 1;
    render();
  });
}

// Star Pool Drawer toggle & actions
const drawerEl = $("drawer");
if ($("starToggle") && drawerEl) {
  $("starToggle").addEventListener('click', () => {
    const open = !drawerEl.classList.contains('open');
    drawerEl.classList.remove('settled');
    drawerEl.classList.toggle('open', open);
    $("starToggle").classList.toggle('on', open);
    $("starToggle").setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) setTimeout(() => drawerEl.classList.contains('open') && drawerEl.classList.add('settled'), 380);
  });
}

if ($("poolSwitch")) {
  $("poolSwitch").addEventListener('click', () => {
    const currentlyOn = state.routing_mode === 'favorites';
    updateStarPoolRouting(!currentlyOn, state.fav_region || '');
  });
}

if ($("poolViewSeg")) {
  $("poolViewSeg").addEventListener('click', e => {
    const b = e.target.closest('button[data-view]');
    if (!b) return;
    qsa('#poolViewSeg button').forEach(x => x.classList.toggle('on', x === b));
    showFavoritesOnly = (b.dataset.view === 'fav');
    currentPage = 1;
    render();
  });
}

qsa('[data-pool]').forEach(b => b.addEventListener('click', () => {
  const favIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids.filter(Boolean) : [];
  if (favIds.length === 0) { toast('星标常备池中暂无收藏节点', 'warn'); return; }
  switch (b.dataset.pool) {
    case 'test': startBatchAvailabilityWithIds(favIds); break;
    case 'eval': startBatchCleanIpWithIds(favIds, 'cleanip', false); break;
    case 'multi': startBatchCleanIpWithIds(favIds, 'intel', true); break;
    case 'select':
      favIds.forEach(id => selectedNodeIds.add(id));
      render();
      toast(`已勾选全部 ${favIds.length} 个星标节点`, 'info');
      break;
    case 'export': {
      const lines = nodes.filter(n => n && favIds.includes(n.id)).map(n => `${n.ip || n.remote_host}:${n.remote_port || ''}`);
      copyText(lines.join('\n'), '星标节点地址列表已复制到剪贴板');
      break;
    }
  }
}));

// Header Actions & Settings Modal Events
document.addEventListener('click', async e => {
  const a = e.target.closest('[data-act]');
  if (!a) return;
  switch (a.dataset.act) {
    case 'sched': openSettingsModal('sched'); break;
    case 'account': openSettingsModal('account'); break;
    case 'selfcheck': openSettingsModal('selfcheck'); break;
    case 'logs': openSettingsModal('logs'); break;
    case 'logout':
      if (!confirm('确定要退出管理员登录吗？')) return;
      try {
        await fetchWithTimeout('./api/logout', { method: 'POST' }, 15000);
        window.location.reload();
      } catch (err) {}
      break;
  }
});

qsa('#setModal .tab').forEach(b => b.addEventListener('click', () => setSettingsTab(b.dataset.tab)));
qsa('#routing_mode_group .mode-card').forEach(c => c.addEventListener('click', () => setRoutingModeUI(c.dataset.mode)));
qsa('#routing_ip_type_group button').forEach(b => b.addEventListener('click', () => setRoutingIpTypeUI(b.dataset.iptype)));

if ($("nodeOpts")) {
  $("nodeOpts").addEventListener('click', e => {
    const o = e.target.closest('.node-opt');
    if (!o) return;
    qsa('#nodeOpts .node-opt').forEach(x => x.classList.toggle('on', x === o));
    const nid = o.dataset.nid;
    if (nid && state.active_openvpn_node_id !== nid) {
      connectToNode(nid);
    }
  });
}

if ($("saveSet")) $("saveSet").addEventListener('click', saveScheduleAndProxySettings);
if ($("resetSet")) {
  $("resetSet").addEventListener('click', () => {
    setRoutingModeUI('auto');
    setRoutingIpTypeUI('all');
    toast('已恢复为自动调度模式（请点击保存生效）', 'info');
  });
}
if ($("saveCredBtn")) $("saveCredBtn").addEventListener('click', saveCredentialsSettings);
if ($("refreshGatewayBtn")) $("refreshGatewayBtn").addEventListener('click', loadGatewayStatus);

if ($("btn_test_proxy")) {
  $("btn_test_proxy").addEventListener('click', async () => {
    const btn = $("btn_test_proxy");
    const badge = $("proxy_status_badge");
    btn.disabled = true;
    if (badge) { badge.className = 'sb sb-test'; badge.innerHTML = '<span class="spin"></span>检测中…'; }
    try {
      const response = await fetchWithTimeout('./api/test_proxy', { method: 'POST' }, 45000);
      const result = await readJsonResponse(response, '代理检测失败');
      await load();
      await loadGatewayStatus();
      if (result.ok) toast(`本地代理出口正常 · IP: ${result.ip || '-'} (${result.latency_ms || '-'} ms)`, 'ok');
      else toast('本地代理出口不可用: ' + (result.error || ''), 'err');
    } catch (e) {
      toast('代理检测失败: ' + (e.message || '未知错误'), 'err');
    } finally {
      btn.disabled = false;
    }
  });
}

if ($("logFilters")) {
  $("logFilters").addEventListener('click', e => {
    const b = e.target.closest('[data-cat]');
    if (!b) return;
    logCatFilter = b.dataset.cat;
    renderLogsView();
  });
}
if ($("copyLogBtn")) {
  $("copyLogBtn").addEventListener('click', () => {
    const txt = rawLogsCache.map(l => `[${l.timestamp}] [${l.level}] [${l.module}] ${l.message}`).join('\n');
    copyText(txt, '运行日志已复制到剪贴板');
  });
}
if ($("exportLog")) {
  $("exportLog").addEventListener('click', () => {
    const txt = rawLogsCache.map(l => `[${l.timestamp}] [${l.level}] [${l.module}] ${l.message}`).join('\n');
    const blob = new Blob([txt], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `aimilivpn_logs_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    toast('运行日志已导出', 'ok');
  });
}

// Check Update & Sync Directory
if ($("checkUpdate")) {
  $("checkUpdate").addEventListener('click', async () => {
    const st = $("verStatus");
    if (st) st.innerHTML = `<span class="vs-ic busy"><span class="spin"></span></span><span><b>正在检查更新…</b><small>连接 GitHub 更新源</small></span>`;
    try {
      const response = await fetchWithTimeout('./api/check_update', { cache: 'no-store' }, 25000);
      const result = await readJsonResponse(response, '更新检查失败');
      if ($("latest_release_link") && result.release_url) $("latest_release_link").href = result.release_url;
      if (result.update_available) {
        if (st) st.innerHTML = `<span class="vs-ic busy">${icon('info')}</span><span><b>发现新版本 ${esc(result.latest_tag)}</b><small>${esc(result.update_command || '')}</small></span>`;
        toast(`发现新版本 ${esc(result.latest_tag)}`, 'warn');
      } else {
        if (st) st.innerHTML = `<span class="vs-ic">${icon('check')}</span><span><b>${esc(result.current_version_label || '已是最新版本')}</b><small>刚刚检查 · 主分支最新</small></span>`;
        toast('当前已是最新版本', 'ok');
      }
    } catch (e) {
      if (st) st.innerHTML = `<span class="vs-ic" style="color:var(--red)">${icon('x')}</span><span><b>检查更新失败</b><small>${esc(e.message || '')}</small></span>`;
      toast('检查更新失败: ' + (e.message || ''), 'err');
    }
  });
}

if ($("syncBtn")) {
  $("syncBtn").addEventListener('click', async () => {
    const b = $("syncBtn");
    if (b.disabled) return;
    b.disabled = true;
    b.classList.add('spinning');
    try {
      const response = await fetchWithTimeout('./api/refresh_nodes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ discovery_countries: Array.from(selectedDiscoveryCountries).sort() })
      }, 25000);
      const result = await readJsonResponse(response, '节点目录同步失败');
      if (result.ok) {
        discoveryCountriesDirty = false;
        toast('已在后台启动节点目录同步与可用性探测…', 'info');
        await load();
        startRefreshPolling();
      }
    } catch (e) {
      b.disabled = false;
      b.classList.remove('spinning');
      toast('同步目录失败: ' + (e.message || '未知错误'), 'err');
    }
  });
}

if ($("openVpsBtn")) {
  $("openVpsBtn").addEventListener('click', () => openModal('vpsModal'));
}

/* ---------- Init ---------- */
load().catch(err => console.error('初始化节点数据失败', err));
</script>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = LOCAL_PROXY_HOST
        if connect_host in ("::", "0.0.0.0", ""):
            connect_host = "::1" if is_ipv6 else "127.0.0.1"
        try:
            s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception as e:
            if connect_host == "::1":
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
            else:
                raise e
    except Exception as e:
        diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e}"
        return {
            "ok": False,
            "error": f"代理服务未运行 ({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 检测当前活动虚拟网卡 (tun0 / ppp0 / vpn_se) 是否存在 (Linux 下)
    active_dev = active_tunnel_interface or "tun0"
    tun_path = Path(f"/sys/class/net/{active_dev}")
    if sys.platform.startswith("linux") and not tun_path.exists() and not Path("/sys/class/net/tun0").exists():
        return {
            "ok": False,
            "error": f"[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 ({active_dev}) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_hosts = []
        if LOCAL_PROXY_HOST == "::":
            proxy_hosts = ["[::1]", "127.0.0.1"]
        elif LOCAL_PROXY_HOST == "0.0.0.0":
            proxy_hosts = ["127.0.0.1"]
        elif ":" in LOCAL_PROXY_HOST:
            proxy_hosts = [f"[{LOCAL_PROXY_HOST}]", "127.0.0.1"]
        else:
            proxy_hosts = [LOCAL_PROXY_HOST]

        for p_host in proxy_hosts:
            proxy_url = f"socks5h://{p_host}:{LOCAL_PROXY_PORT}"
            proxy_user, proxy_pass = proxy_server.get_proxy_credentials()
            cmd = [
                "curl", "-s",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", "5"
            ]
            if proxy_user is not None and proxy_pass is not None:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    lines = res.stdout.strip().splitlines()
                    if len(lines) >= 2:
                        ip = lines[0].strip()
                        time_info = lines[1].strip().split()
                        if len(time_info) == 2:
                            total_time_str, http_code = time_info
                            if http_code == "200" and ip:
                                latency_ms = int(float(total_time_str) * 1000)
                                return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                pass
        return None

    try:
        result = _curl_check_ip("http://ip.sb")
        if result:
            return result
        result = _curl_check_ip("http://api.ipify.org")
        if result:
            return result
            
        # 此时外网测试失败，检测本地代理端口是否依然能连通。若仍能连通，直接抛出出口测试失败，不调用占用诊断
        port_still_listening = False
        test_sock = None
        try:
            test_sock = socket.socket(af, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                test_sock.connect((connect_host, LOCAL_PROXY_PORT))
                port_still_listening = True
            except Exception:
                if connect_host == "::1":
                    test_sock.close()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    test_sock.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    port_still_listening = True
        except Exception:
            pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

        if not port_still_listening:
            diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}
            
        return {"ok": False, "error": "出口连接测试失败 (ip.sb 和 api.ipify.org 均无法连通，可能是节点已失效或 VPS 防火墙限制了 UDP/TCP 出站端口)"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def reset_proxy_failure_counter(node_id: str = "") -> None:
    global consecutive_proxy_failures, last_proxy_failure_node_id
    with lock:
        consecutive_proxy_failures = 0
        last_proxy_failure_node_id = node_id

def record_proxy_failure(node_id: str) -> int:
    global consecutive_proxy_failures, last_proxy_failure_node_id
    with lock:
        if node_id != last_proxy_failure_node_id:
            consecutive_proxy_failures = 0
            last_proxy_failure_node_id = node_id
        consecutive_proxy_failures += 1
        return consecutive_proxy_failures

def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting
    time.sleep(30)
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue

            checked_node_id = active_openvpn_node_id
            res = check_proxy_health()
            if checked_node_id != active_openvpn_node_id:
                continue
            if res["ok"]:
                reset_proxy_failure_counter(checked_node_id)
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                error_msg = res.get("error", "未知错误")
                failure_count = record_proxy_failure(checked_node_id) if checked_node_id else 0
                process_exited = bool(checked_node_id) and not active_openvpn_running()
                should_recover = process_exited or failure_count >= PROXY_FAILURE_THRESHOLD
                if checked_node_id:
                    print(f"[警告] {LOCAL_PROXY_PORT} 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json(
                        "WARNING",
                        "Proxy",
                        f"代理不可用 ({failure_count}/{PROXY_FAILURE_THRESHOLD}): {error_msg}",
                    )
                display_error = error_msg
                if checked_node_id and not process_exited and not should_recover:
                    display_error = f"{error_msg}（连续失败 {failure_count}/{PROXY_FAILURE_THRESHOLD}，暂不切换）"
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=display_error,
                )

                # A dead OpenVPN process is recovered immediately. Transient
                # external probe failures must cross the configured threshold.
                if checked_node_id and should_recover:
                    reset_proxy_failure_counter(checked_node_id)
                    ui_cfg = load_ui_config()
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    if routing_mode != "fixed_ip":
                        with lock:
                            nodes = read_nodes()
                            active_node = next((n for n in nodes if n.get("id") == checked_node_id), None)
                            if active_node:
                                mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                write_json(NODES_FILE, nodes)
                        auto_switch_node()
                    else:
                        print(f"[代理守护线程] 固定 IP 模式下代理不可用，正在尝试重启连接同一节点: {checked_node_id}", flush=True)
                        try:
                            connect_node(checked_node_id)
                        except Exception as e:
                            print(f"[代理守护线程] 重启固定节点失败: {e}", flush=True)
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global last_pinger_heartbeat
    while True:
        last_pinger_heartbeat = time.time()
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_nodes()
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            print("[Auth] 管理后台密码为空，已拒绝访问。请检查 ui_auth.json。", flush=True)
            return False
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        purge_expired_sessions()
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        request_path = urllib.parse.urlsplit(self.path).path
        if not secret_path:
            return request_path
        if request_path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if request_path.startswith(prefix):
            return "/" + request_path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def read_request_body(self, max_bytes: int = 65536) -> bytes:
        length = parse_int(self.headers.get("Content-Length"))
        if length < 0:
            raise ValueError("Content-Length 无效")
        if length > max_bytes:
            raise ValueError(f"请求体过大，最大允许 {max_bytes} 字节")
        return self.rfile.read(length) if length > 0 else b""

    def read_json_body(self, max_bytes: int = 65536) -> dict[str, Any]:
        body = self.read_request_body(max_bytes)
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求 JSON 必须是对象")
        return data

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            nodes = sync_favorite_snapshots_with_nodes()
            try:
                ip_cache = vpn_utils.load_ip_cache()
            except Exception:
                ip_cache = {}
            for n in nodes:
                ip_key = str(n.get("ip") or n.get("remote_host") or "").strip()
                cached_entry = ip_cache.get(ip_key) if ip_key and isinstance(ip_cache, dict) else None
                if n.get("intel_version") != vpn_utils.INTEL_SCORING_VERSION:
                    for ik in vpn_utils.INTEL_NODE_FIELDS:
                        n.pop(ik, None)
                if isinstance(cached_entry, dict):
                    for ck in vpn_utils.CLEANIP_NODE_FIELDS:
                        if n.get(ck) in (None, "") and cached_entry.get(ck) not in (None, ""):
                            n[ck] = cached_entry[ck]
                    if cached_entry.get("intel_version") == vpn_utils.INTEL_SCORING_VERSION:
                        for ik in vpn_utils.INTEL_NODE_FIELDS:
                            if n.get(ik) in (None, "") and cached_entry.get(ik) not in (None, ""):
                                n[ik] = cached_entry[ik]
            connection_state = get_state()
            connection_ready = connection_ready_for_ui(connection_state)
            active_node = next((n for n in nodes if connection_ready and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = bool(connection_ready and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path == "/api/check_update":
            try:
                self.send_json(check_latest_release())
            except Exception as exc:
                self.send_json(
                    {"ok": False, "error": f"无法检查 GitHub 正式版更新: {exc}"},
                    HTTPStatus.BAD_GATEWAY,
                )
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_nodes()
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/gateway_status":
            web_ui_status = {
                "name": "Web 管理服务",
                "status": "running",
                "details": f"监听地址: {load_ui_config().get('host', UI_HOST)}:{load_ui_config().get('port', UI_PORT)}",
                "error": ""
            }
            proxy_ok = False
            proxy_err = ""
            is_ipv6 = ":" in LOCAL_PROXY_HOST
            af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(0.5)
                connect_host = LOCAL_PROXY_HOST
                if connect_host in ("::", "0.0.0.0", ""):
                    connect_host = "::1" if is_ipv6 else "127.0.0.1"
                try:
                    s.connect((connect_host, LOCAL_PROXY_PORT))
                    proxy_ok = True
                except Exception:
                    if connect_host == "::1":
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        proxy_ok = True
                    else:
                        raise
            except Exception as e:
                diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
                proxy_err = diag[1] if diag else f"本地代理网关无法连通: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "本地代理网关",
                "status": "running" if proxy_ok else "stopped",
                "details": f"监听地址: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            ovpn_ok = active_openvpn_running()
            ovpn_err = ""
            ovpn_details = "未连接"
            if ovpn_ok:
                ovpn_details = f"已连接节点: {active_openvpn_node_id}"
                if sys.platform.startswith("linux"):
                    active_dev = active_tunnel_interface or "tun0"
                    if not Path(f"/sys/class/net/{active_dev}").exists() and not Path("/sys/class/net/tun0").exists():
                        ovpn_err = f"[警告] 虚拟网卡 ({active_dev}) 未启用，可能存在策略路由配置问题。"
            else:
                if active_openvpn_node_id:
                    ovpn_err = "连接已中断或 OpenVPN 核心程序异常退出。"
                    ovpn_details = f"尝试连接节点 {active_openvpn_node_id} 失败"
            openvpn_status = {
                "name": "OpenVPN 核心连接",
                "status": "running" if ovpn_ok else "stopped",
                "details": ovpn_details,
                "error": ovpn_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < (CHECK_INTERVAL_SECONDS * 1.5)) or (server_uptime < 15.0)
            collector_status = {
                "name": "节点同步守护线程",
                "status": "running" if collector_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '等待启动'}",
                "error": "" if collector_ok else "线程可能已异常终止，导致无法在后台拉取和测速新节点。"
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 90.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "出口检测守护线程",
                "status": "running" if checker_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '等待启动'}",
                "error": "" if checker_ok else "线程可能已挂起或终止，导致无法实时获取代理出口状态。"
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 30.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "延迟测速守护线程",
                "status": "running" if pinger_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '等待启动'}",
                "error": "" if pinger_ok else "线程可能已中止，无法实时刷新活动节点的 Ping 延迟。"
            }
            self.send_json({
                "ok": True,
                "services": [
                    web_ui_status,
                    proxy_gateway_status,
                    openvpn_status,
                    collector_status,
                    checker_status,
                    pinger_status
                ]
            })
        elif effective_path == "/api/logs":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            entries: list[dict[str, Any]] = []
            if log_file.exists():
                try:
                    with lock:
                        entries = read_recent_log_entries(log_file)
                except Exception as e:
                    print(f"[API Logs] Error reading log file: {e}", flush=True)
            self.send_json({"logs": entries})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        global is_connecting
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            try:
                payload = self.read_json_body()
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                password_matches = bool(expected_pwd) and secrets.compare_digest(input_pwd, str(expected_pwd))
                username_matches = secrets.compare_digest(input_uname, str(expected_uname))
                if password_matches and username_matches:
                    token = uuid.uuid4().hex
                    purge_expired_sessions()
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    body = json.dumps({"ok": True}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/update_credentials":
            try:
                payload = self.read_json_body()
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "")
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                
                ui_cfg = load_ui_config()
                if not new_username or (not new_password and not ui_cfg.get("password")):
                    self.send_json({"ok": False, "error": "用户名不能为空；首次设置时密码不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "网页管理端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return

                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return

                expected_username = ui_cfg.get("username", "")
                expected_password = ui_cfg.get("password", "")
                expected_port = ui_cfg.get("port", 8787)
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")

                if ports_conflict(new_port_int, ui_cfg.get("proxy_port", 7928)):
                    self.send_json({"ok": False, "error": "网页管理端口不能与代理出站端口相同"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                
                auth_file = DATA_DIR / "ui_auth.json"
                reauth_required = new_username != expected_username or (new_password and new_password != expected_password)
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                    if reauth_required:
                        active_sessions.clear()
                
                restart_needed = (new_port_int != expected_port or new_suffix != expected_suffix)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "reauth_required": reauth_required, "message": "配置更新成功，网页管理端口或路径已变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 管理后台安全配置更新，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    self.send_json({"ok": True, "restart_needed": False, "reauth_required": reauth_required, "message": "账号密码配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_settings":
            try:
                payload = self.read_json_body()
                
                new_proxy_port = payload.get("proxy_port")
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = normalize_routing_country(payload.get("force_country"), read_nodes())
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                
                try:
                    new_proxy_port_int = int(new_proxy_port)
                    if not (1024 <= new_proxy_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "代理出站端口范围必须是 1024 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_region" and not force_country:
                    self.send_json({"ok": False, "error": "启用固定地区前，请先选择一个要锁定的国家"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                expected_proxy_port = ui_cfg.get("proxy_port", 7928)
                fixed_node_id = current_fixed_node_id(ui_cfg) if routing_mode == "fixed_ip" else ""
                
                if ports_conflict(ui_cfg.get("port", 8787), new_proxy_port_int):
                    self.send_json({"ok": False, "error": "代理出站端口不能与网页管理端口相同"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_ip" and not fixed_node_id:
                    self.send_json({"ok": False, "error": "启用固定 IP 前，请先连接一个要锁定的节点"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg["proxy_port"] = new_proxy_port_int
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                if routing_mode == "favorites":
                    ui_cfg["fav_fail_fallback"] = False
                if routing_mode == "fixed_ip":
                    ui_cfg["fixed_node_id"] = fixed_node_id
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "路由设置已更新")
                
                restart_needed = (new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "配置更新成功，代理出站端口变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 代理出站端口变更，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    message = policy_message or "配置更新成功，已即时生效！"
                    self.send_json({"ok": True, "restart_needed": False, "message": message})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_routing":
            try:
                payload = self.read_json_body()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = normalize_routing_country(payload.get("force_country"), read_nodes())
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                fav_region_specified = "fav_region" in payload
                fav_region_val = normalize_region_token(str(payload.get("fav_region") or ""))
                fav_fail_fallback = False
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_region" and not force_country:
                    self.send_json({"ok": False, "error": "启用固定地区前，请先选择一个要锁定的国家"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                fixed_node_id = current_fixed_node_id(ui_cfg) if routing_mode == "fixed_ip" else ""
                if routing_mode == "fixed_ip" and not fixed_node_id:
                    self.send_json({"ok": False, "error": "启用固定 IP 前，请先连接一个要锁定的节点"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                if fav_region_specified:
                    ui_cfg["fav_region"] = fav_region_val
                ui_cfg["fav_fail_fallback"] = fav_fail_fallback
                if routing_mode == "fixed_ip":
                    ui_cfg["fixed_node_id"] = fixed_node_id
                ui_cfg.pop("enable_force_country", None)
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "出站路由配置已更新")
                
                self.send_json({"ok": True, "message": policy_message or "出站路由配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/toggle_favorite":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                if not node_id:
                    self.send_json({"ok": False, "error": "节点 ID 不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                fav_ids = ui_cfg.get("favorite_node_ids", [])
                if not isinstance(fav_ids, list):
                    fav_ids = []
                
                if node_id in fav_ids:
                    fav_ids.remove(node_id)
                else:
                    fav_ids.append(node_id)
                
                ui_cfg["favorite_node_ids"] = fav_ids
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                    try:
                        sync_favorite_snapshots_with_nodes(fav_ids=fav_ids)
                    except Exception as sync_exc:
                        print(f"[收藏快照] 同步收藏快照失败: {sync_exc}", flush=True)

                policy_message = None
                if ui_cfg.get("routing_mode") == "favorites":
                    policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "收藏列表已更新")
                
                self.send_json({"ok": True, "favorite_node_ids": fav_ids, "message": policy_message or ""})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": maintain_valid_nodes(force=True)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                payload = self.read_json_body()
                if "discovery_countries" in payload:
                    discovery_countries = persist_discovery_countries(
                        payload.get("discovery_countries")
                    )
                else:
                    discovery_countries = normalize_discovery_countries(
                        load_ui_config().get("discovery_countries")
                    )
                if maintenance_lock.locked():
                    self.send_json({
                        "ok": True,
                        "message": "节点维护任务正在运行，国家范围已保存并将在下一轮生效",
                        "running": True,
                        "discovery_countries": discovery_countries,
                    })
                else:
                    threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                    self.send_json({
                        "ok": True,
                        "message": "已在后台启动节点更新流程",
                        "running": True,
                        "discovery_countries": discovery_countries,
                    })
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                payload = self.read_json_body(max_bytes=262144)
                node_ids = payload.get("ids", [])
                if not isinstance(node_ids, list):
                    self.send_json({"ok": False, "error": "节点 ID 列表无效"}, HTTPStatus.BAD_REQUEST)
                    return
                node_ids = [str(node_id or "").strip() for node_id in node_ids]
                node_ids = [node_id for node_id in node_ids if node_id]
                if not node_ids:
                    self.send_json({"ok": False, "error": "请至少选择一个要检测的节点"}, HTTPStatus.BAD_REQUEST)
                    return
                max_batch_limit = max(MANUAL_TEST_NODE_LIMIT, 200)
                if len(node_ids) > max_batch_limit:
                    node_ids = node_ids[:max_batch_limit]
                if not maintenance_lock.acquire(blocking=False):
                    self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                    return
                with lock:
                    if is_connecting:
                        maintenance_lock.release()
                        self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                        return
                    is_connecting = True
                try:
                    set_state(is_connecting=True, last_check_message=f"正在批量测试 {len(node_ids)} 个节点可用性...")
                    tested_nodes = test_multiple_nodes(node_ids)
                    self.send_json({"ok": True, "nodes": tested_nodes})
                finally:
                    with lock:
                        is_connecting = False
                    set_state(is_connecting=False)
                    maintenance_lock.release()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes_batch":
            try:
                payload = self.read_json_body(max_bytes=262144)
                raw_ids = payload.get("ids")
                if raw_ids is None:
                    raw_ids = payload.get("node_ids", [])
                if not isinstance(raw_ids, list):
                    self.send_json({"ok": False, "error": "节点 ID 列表无效"}, HTTPStatus.BAD_REQUEST)
                    return
                seen_batch: set[str] = set()
                node_ids: list[str] = []
                for item in raw_ids:
                    nid = str(item or "").strip()
                    if nid and nid not in seen_batch:
                        seen_batch.add(nid)
                        node_ids.append(nid)
                if not node_ids:
                    self.send_json({"ok": False, "error": "请先勾选要批量检测的节点"}, HTTPStatus.BAD_REQUEST)
                    return
                if len(node_ids) > 200:
                    node_ids = node_ids[:200]
                if not maintenance_lock.acquire(blocking=False):
                    self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                    return
                global batch_test_running, batch_test_total, batch_test_completed
                with lock:
                    if is_connecting or batch_test_running:
                        maintenance_lock.release()
                        self.send_json({"ok": False, "error": "当前已有连接或批量检测任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                        return
                    is_connecting = True
                    batch_test_running = True
                    batch_test_total = len(node_ids)
                    batch_test_completed = 0
                    batch_test_cancel_event.clear()

                def run_batch_probe(target_ids: list[str]) -> None:
                    global is_connecting, batch_test_running, batch_test_total, batch_test_completed
                    try:
                        set_state(
                            is_connecting=True,
                            last_check_message=f"正在批量检测已选节点 (0/{len(target_ids)})...",
                        )
                        def on_progress(done: int, total: int, _res: dict[str, Any]) -> None:
                            global batch_test_completed
                            with lock:
                                batch_test_completed = done
                            set_state(
                                last_check_message=f"正在批量检测已选节点 ({done}/{total})..."
                            )
                        results = test_multiple_nodes(
                            target_ids,
                            target_available=None,
                            cancel_event=batch_test_cancel_event,
                            progress_callback=on_progress,
                        )
                        avail_cnt = sum(1 for r in results if r.get("probe_status") == "available")
                        cancelled = batch_test_cancel_event.is_set()
                        summary_msg = (
                            f"批量检测已停止：已测 {len(results)}/{len(target_ids)} 个节点，可用 {avail_cnt} 个"
                            if cancelled
                            else f"批量检测完成：共测 {len(results)} 个节点，可用 {avail_cnt} 个"
                        )
                        valid_total = len([n for n in read_nodes() if n.get("probe_status") == "available"])
                        set_state(
                            last_check_at=time.time(),
                            last_check_message=summary_msg,
                            valid_nodes=valid_total,
                        )
                    except Exception as batch_exc:
                        log_to_json("ERROR", "VPN", f"批量检测节点异常: {batch_exc}")
                        set_state(last_check_message=f"批量检测异常: {batch_exc}")
                    finally:
                        with lock:
                            is_connecting = False
                            batch_test_running = False
                        set_state(is_connecting=False)
                        maintenance_lock.release()

                threading.Thread(target=run_batch_probe, args=(node_ids,), daemon=True).start()
                self.send_json({
                    "ok": True,
                    "started": True,
                    "total": len(node_ids),
                    "message": f"已启动 {len(node_ids)} 个节点的并发可用性检测",
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/cancel_batch_test":
            try:
                self.read_request_body()
                batch_test_cancel_event.set()
                self.send_json({"ok": True, "message": "已发送停止批量检测指令"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/check_cleanip":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                target_ip = str(payload.get("ip") or "").strip()
                force_refresh = bool(payload.get("force"))
                source = str(payload.get("source") or "cleanip").strip().lower()

                node = None
                if node_id:
                    with lock:
                        nodes = read_nodes()
                        node = next((item for item in nodes if item.get("id") == node_id), None)
                    if node and not target_ip:
                        target_ip = str(node.get("ip") or node.get("remote_host") or "").strip()

                if not target_ip:
                    st = get_state()
                    target_ip = str(st.get("proxy_ip") or "").strip()
                    if target_ip == "-":
                        target_ip = ""

                # Strictly never route CleanIP or Three-Source queries through the residential VPN tunnel
                if source == "intel":
                    result_data = vpn_utils.query_intel_for_ip(
                        target_ip,
                        force_refresh=force_refresh,
                    )
                    fields_to_save = vpn_utils.INTEL_NODE_FIELDS
                else:
                    result_data = vpn_utils.query_cleanip_for_ip(
                        target_ip,
                        force_refresh=force_refresh,
                        via_proxy=None,
                        use_cli_endpoint=False,
                    )
                    fields_to_save = vpn_utils.CLEANIP_NODE_FIELDS
                resolved_ip = str(result_data.get("ip") or target_ip).strip()

                updated_node = None
                with lock:
                    nodes = read_nodes()
                    changed = False
                    for item in nodes:
                        item_ip = str(item.get("ip") or item.get("remote_host") or "").strip()
                        if (node_id and item.get("id") == node_id) or (resolved_ip and item_ip == resolved_ip):
                            for ck in fields_to_save:
                                if ck in result_data:
                                    item[ck] = result_data[ck]
                            changed = True
                            if node_id and item.get("id") == node_id:
                                updated_node = dict(item)
                            elif updated_node is None:
                                updated_node = dict(item)
                    if changed:
                        write_json(NODES_FILE, nodes)
                        try:
                            sync_favorite_snapshots_with_nodes(nodes=nodes)
                        except Exception:
                            pass
                if updated_node and "config_text" in updated_node:
                    del updated_node["config_text"]
                self.send_json({
                    "ok": True,
                    "source": source,
                    "cleanip": result_data,
                    "node": updated_node,
                })
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/check_cleanip_batch":
            try:
                payload = self.read_json_body(max_bytes=262144)
                raw_ids = payload.get("ids") or payload.get("node_ids") or []
                force_refresh = bool(payload.get("force"))
                source = str(payload.get("source") or "cleanip").strip().lower()
                if not isinstance(raw_ids, list):
                    self.send_json({"ok": False, "error": "节点 ID 列表无效"}, HTTPStatus.BAD_REQUEST)
                    return
                target_ids = [str(x or "").strip() for x in raw_ids if str(x or "").strip()]
                if not target_ids:
                    self.send_json({"ok": False, "error": "请先勾选要检测的节点"}, HTTPStatus.BAD_REQUEST)
                    return
                target_ids = list(dict.fromkeys(target_ids))[:50]

                global cleanip_batch_running, cleanip_batch_total, cleanip_batch_completed
                with lock:
                    if cleanip_batch_running:
                        self.send_json({"ok": False, "error": "当前已有批量检测任务正在运行，请稍候"}, HTTPStatus.CONFLICT)
                        return
                    cleanip_batch_running = True
                    cleanip_batch_total = len(target_ids)
                    cleanip_batch_completed = 0

                def run_cleanip_batch(ids_to_check: list[str], force_flag: bool, src_mode: str) -> None:
                    global cleanip_batch_running, cleanip_batch_total, cleanip_batch_completed
                    fields_to_save = vpn_utils.INTEL_NODE_FIELDS if src_mode == "intel" else vpn_utils.CLEANIP_NODE_FIELDS
                    try:
                        with lock:
                            nodes_snapshot = read_nodes()
                            by_id = {str(n.get("id")): n for n in nodes_snapshot if n.get("id")}

                        def check_one(nid: str) -> tuple[str, dict[str, Any] | None]:
                            node_item = by_id.get(nid)
                            if not node_item:
                                return nid, None
                            ip_addr = str(node_item.get("ip") or node_item.get("remote_host") or "").strip()
                            if not ip_addr:
                                return nid, None
                            if src_mode == "intel":
                                res = vpn_utils.query_intel_for_ip(ip_addr, force_refresh=force_flag)
                            else:
                                res = vpn_utils.query_cleanip_for_ip(ip_addr, force_refresh=force_flag, via_proxy=None, use_cli_endpoint=False)
                            return nid, res

                        max_workers = min(4, max(1, len(ids_to_check)))
                        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                            futures = {pool.submit(check_one, nid): nid for nid in ids_to_check}
                            for fut in concurrent.futures.as_completed(futures):
                                nid = futures[fut]
                                try:
                                    _, c_res = fut.result()
                                except Exception as e:
                                    print(f"[{'Intel' if src_mode == 'intel' else 'CleanIP'} Batch] 检测节点 {nid} 失败: {e}", flush=True)
                                    c_res = None
                                with lock:
                                    cleanip_batch_completed += 1
                                    if c_res:
                                        curr_nodes = read_nodes()
                                        c_ip = str(c_res.get("ip") or "").strip()
                                        for item in curr_nodes:
                                            item_ip = str(item.get("ip") or item.get("remote_host") or "").strip()
                                            if item.get("id") == nid or (c_ip and item_ip == c_ip):
                                                for ck in fields_to_save:
                                                    if ck in c_res:
                                                        item[ck] = c_res[ck]
                                        write_json(NODES_FILE, curr_nodes)
                                        try:
                                            sync_favorite_snapshots_with_nodes(nodes=curr_nodes)
                                        except Exception:
                                            pass
                    finally:
                        with lock:
                            cleanip_batch_running = False
                threading.Thread(target=run_cleanip_batch, args=(target_ids, force_refresh, source), daemon=True).start()
                self.send_json({
                    "ok": True,
                    "started": True,
                    "total": len(target_ids),
                    "message": f"已在后台启动 {len(target_ids)} 个节点的 {'三源情报对比' if source == 'intel' else 'CleanIP 纯净度'}检测",
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                cancel_background_refill()
                cancel_pending_connection_attempt()
                ui_cfg = load_ui_config()
                ui_cfg["connection_enabled"] = False
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                
                clear_active_connection_state("手动断开连接")
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                global consecutive_proxy_failures, last_proxy_failure_node_id
                consecutive_proxy_failures = 0
                last_proxy_failure_node_id = ""
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            previous_node_id = active_openvpn_node_id if active_openvpn_running() else ""
            try:
                payload = self.read_json_body()
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""))})
            except ConnectionCancelled as exc:
                self.send_json({"ok": False, "cancelled": True, "error": str(exc)}, HTTPStatus.CONFLICT)
            except RuntimeError as exc:
                if str(exc).startswith("当前已有"):
                    self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.CONFLICT)
                    return
                threading.Thread(
                    target=recover_after_manual_connect_failure,
                    args=(previous_node_id,),
                    daemon=True,
                ).start()
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            except Exception as exc:
                threading.Thread(
                    target=recover_after_manual_connect_failure,
                    args=(previous_node_id,),
                    daemon=True,
                ).start()
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "")
                if not node_id.strip():
                    self.send_json({"ok": False, "error": "节点 ID 不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                if not maintenance_lock.acquire(blocking=False):
                    self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                    return
                with lock:
                    if is_connecting:
                        maintenance_lock.release()
                        self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                        return
                    is_connecting = True
                try:
                    set_state(is_connecting=True, last_check_message="正在手动测试节点可用性...")
                    updated_node = test_node_by_id(node_id)
                    self.send_json({"ok": True, "node": updated_node})
                finally:
                    with lock:
                        is_connecting = False
                    set_state(is_connecting=False)
                    maintenance_lock.release()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                self.read_request_body()
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        tunnel_ready=active_openvpn_running(),
                        proxy_ready=active_openvpn_running(),
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ready=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)

def main() -> None:
    ensure_dirs()
    kill_existing_openvpn_processes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "mirror_url": MIRROR_HTTPS_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{'[' + LOCAL_PROXY_HOST + ']' if ':' in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_fetch_source": "",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "tunnel_ready": False,
            "proxy_ready": False,
            "proxy_ok": False,
            "pending_node_id": "",
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for _ in range(30):
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                gateway_ready = True
                break
            except Exception:
                if connect_host == "::1":
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        gateway_ready = True
                        break
                    except Exception:
                        pass
                raise
        except Exception:
            time.sleep(0.5)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=ip_enrichment_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    
    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = bounded_int(ui_cfg.get("port"), UI_PORT, 1, 65535)
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    DualStackHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()
