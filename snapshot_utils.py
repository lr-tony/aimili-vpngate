from __future__ import annotations

import base64
import csv
import io
import re
from typing import Any


MAX_SNAPSHOT_BYTES = 12 * 1024 * 1024
MAX_CONFIG_BYTES = 128 * 1024

REQUIRED_COLUMNS = {
    "HostName",
    "IP",
    "Score",
    "Ping",
    "Speed",
    "CountryLong",
    "CountryShort",
    "NumVpnSessions",
    "OpenVPN_ConfigData_Base64",
}

# VPNGate profiles are data, but OpenVPN profiles can also launch programs.
# Keep the accepted surface limited to connection and TLS settings.
SAFE_DIRECTIVES = {
    "auth",
    "cipher",
    "client",
    "comp-lzo",
    "compress",
    "connect-retry",
    "connect-retry-max",
    "connect-timeout",
    "data-ciphers",
    "data-ciphers-fallback",
    "dev",
    "dev-type",
    "dhcp-option",
    "explicit-exit-notify",
    "keepalive",
    "key-direction",
    "mute",
    "nobind",
    "persist-key",
    "persist-tun",
    "ping",
    "ping-restart",
    "ping-timer-rem",
    "proto",
    "pull",
    "rcvbuf",
    "remote",
    "remote-cert-tls",
    "remote-random",
    "remote-random-hostname",
    "reneg-sec",
    "resolv-retry",
    "route-delay",
    "sndbuf",
    "tls-cipher",
    "tls-ciphersuites",
    "tls-client",
    "tls-version-min",
    "verb",
    "verify-x509-name",
}
SAFE_INLINE_BLOCKS = {"ca", "cert", "key", "tls-auth", "tls-crypt"}


def decode_config(encoded: str) -> str:
    compact = "".join(str(encoded or "").split())
    if not compact:
        raise ValueError("OpenVPN configuration is empty")
    raw = base64.b64decode(compact.encode("ascii"), validate=True)
    if not raw or len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("OpenVPN configuration size is invalid")
    return raw.decode("utf-8", errors="strict")


def validate_openvpn_config(config_text: str) -> None:
    if not config_text or len(config_text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ValueError("OpenVPN configuration size is invalid")
    if "\x00" in config_text:
        raise ValueError("OpenVPN configuration contains a NUL byte")

    directives: set[str] = set()
    current_block: str | None = None
    remote_seen = False
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("<") and line.endswith(">"):
            tag = line[1:-1].strip().lower()
            if tag.startswith("/"):
                if current_block != tag[1:]:
                    raise ValueError(f"Unexpected closing OpenVPN block: {tag}")
                current_block = None
                continue
            if current_block is not None or tag not in SAFE_INLINE_BLOCKS:
                raise ValueError(f"Unsafe OpenVPN inline block: {tag}")
            current_block = tag
            directives.add(f"<{tag}>")
            continue
        if current_block is not None:
            continue

        parts = re.split(r"\s+", line)
        directive = parts[0].lstrip("-").lower()
        if directive not in SAFE_DIRECTIVES:
            raise ValueError(f"Unsafe OpenVPN directive: {directive}")
        directives.add(directive)

        if directive == "remote":
            if len(parts) < 3:
                raise ValueError("OpenVPN remote directive is incomplete")
            try:
                port = int(parts[2])
            except ValueError as exc:
                raise ValueError("OpenVPN remote port is invalid") from exc
            if not (1 <= port <= 65535):
                raise ValueError("OpenVPN remote port is out of range")
            remote_seen = True
        elif directive == "dev" and (len(parts) < 2 or not re.fullmatch(r"tun\d*", parts[1].lower())):
            raise ValueError("Only TUN OpenVPN devices are accepted")

    if current_block is not None:
        raise ValueError(f"Unclosed OpenVPN inline block: {current_block}")
    if "client" not in directives or not remote_seen:
        raise ValueError("OpenVPN client or remote directive is missing")
    if not {"<ca>", "<cert>", "<key>"}.issubset(directives):
        raise ValueError("OpenVPN certificate blocks are incomplete")


def parse_and_validate_snapshot(text: str, max_rows: int | None = None) -> list[dict[str, str]]:
    raw_size = len(text.encode("utf-8"))
    if raw_size <= 0 or raw_size > MAX_SNAPSHOT_BYTES:
        raise ValueError("VPNGate snapshot size is invalid")

    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if not lines:
        raise ValueError("VPNGate snapshot is empty")
    if lines[0].startswith("#"):
        lines[0] = lines[0][1:]

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    fieldnames = set(reader.fieldnames or [])
    if not REQUIRED_COLUMNS.issubset(fieldnames):
        raise ValueError("VPNGate snapshot columns are incomplete")

    rows: list[dict[str, str]] = []
    for row in reader:
        normalized = {str(key): str(value or "") for key, value in row.items() if key is not None}
        if not normalized.get("IP") or not normalized.get("OpenVPN_ConfigData_Base64"):
            continue
        try:
            config_text = decode_config(normalized["OpenVPN_ConfigData_Base64"])
            validate_openvpn_config(config_text)
        except (UnicodeError, ValueError):
            continue
        rows.append(normalized)
        if max_rows is not None and len(rows) >= max_rows:
            break
    if not rows:
        raise ValueError("VPNGate snapshot contains no valid nodes")
    return rows


def snapshot_summary(text: str) -> dict[str, Any]:
    rows = parse_and_validate_snapshot(text)
    return {"row_count": len(rows), "byte_count": len(text.encode("utf-8"))}


def parse_vpngate_web_html(html_text: str, max_rows: int | None = None) -> list[dict[str, Any]]:
    """
    Parse VPNGate official web table HTML (https://www.vpngate.net/en/) into structured records,
    including nodes that only enable SoftEther SSL-VPN or MS-SSTP without OpenVPN config files,
    as well as dual TCP+UDP port metadata from do_openvpn.aspx links.
    """
    if not html_text or "vg_table_row_" not in html_text:
        return []

    raw_rows = re.split(r"<tr[^>]*>", html_text, flags=re.IGNORECASE)
    results: list[dict[str, Any]] = []

    for row_html in raw_rows:
        if "vg_table_row_" not in row_html:
            continue
        tds = re.split(r"<td[^>]*>", row_html, flags=re.IGNORECASE)[1:]
        if len(tds) < 10:
            continue

        # Column 0: Flag + CountryLong
        flag_m = re.search(r"flags/([A-Za-z]{2})\.png", tds[0], flags=re.IGNORECASE)
        country_short = flag_m.group(1).upper() if flag_m else "XX"
        country_long = re.sub(r"<[^>]+>", " ", tds[0]).strip()
        country_long = re.sub(r"\s+", " ", country_long)

        # Column 1: FQDN (vpnXXXX.opengw.net), IP, PTR
        fqdn_m = re.search(r"([a-zA-Z0-9_-]+)\.opengw\.net", tds[1], flags=re.IGNORECASE)
        host_name = fqdn_m.group(1) if fqdn_m else ""
        ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", tds[1])
        ip = ip_m.group(1) if ip_m else ""
        if not ip:
            continue

        # Column 2: Sessions
        sess_m = re.search(r"([\d,]+)\s*sessions?", tds[2], flags=re.IGNORECASE)
        sessions = int(sess_m.group(1).replace(",", "")) if sess_m else 0

        # Column 3: Speed (Mbps) + Ping (ms)
        speed_m = re.search(r"([\d.]+)\s*Mbps", tds[3], flags=re.IGNORECASE)
        speed_bps = int(float(speed_m.group(1)) * 1_000_000) if speed_m else 0
        ping_m = re.search(r"Ping:\s*<b>\s*(\d+)\s*ms", tds[3], flags=re.IGNORECASE) or re.search(
            r"\b(\d+)\s*ms\b", tds[3], flags=re.IGNORECASE
        )
        ping = int(ping_m.group(1)) if ping_m else 0

        # Column 4: SoftEther SSL-VPN
        ssl_text = re.sub(r"<[^>]+>", " ", tds[4])
        has_sslvpn = bool(re.search(r"SSL-VPN", ssl_text, flags=re.IGNORECASE))
        ssl_tcp_m = re.search(r"TCP:\s*(\d+)", ssl_text, flags=re.IGNORECASE)
        ssl_tcp_port = int(ssl_tcp_m.group(1)) if ssl_tcp_m else 0

        # Column 5: L2TP/IPsec
        has_l2tp = bool(re.search(r"L2TP", tds[5], flags=re.IGNORECASE))

        # Column 6: OpenVPN
        ovpn_m = re.search(r"do_openvpn\.aspx\?([^'\"\s>]+)", tds[6], flags=re.IGNORECASE)
        has_ovpn = bool(ovpn_m)
        ovpn_tcp_port = 0
        ovpn_udp_port = 0
        if ovpn_m:
            qs = ovpn_m.group(1)
            tm = re.search(r"(?:^|[&?])tcp=(\d+)", qs, flags=re.IGNORECASE)
            um = re.search(r"(?:^|[&?])udp=(\d+)", qs, flags=re.IGNORECASE)
            ovpn_tcp_port = int(tm.group(1)) if tm else 0
            ovpn_udp_port = int(um.group(1)) if um else 0
        else:
            ovpn_text = re.sub(r"<[^>]+>", " ", tds[6])
            tm = re.search(r"TCP:\s*(\d+)", ovpn_text, flags=re.IGNORECASE)
            um = re.search(r"UDP:\s*(\d+)", ovpn_text, flags=re.IGNORECASE)
            ovpn_tcp_port = int(tm.group(1)) if tm else 0
            ovpn_udp_port = int(um.group(1)) if um else 0

        # Column 7: MS-SSTP
        sstp_text = re.sub(r"<[^>]+>", " ", tds[7])
        has_sstp = bool(re.search(r"MS-SSTP|SSTP\s+Hostname", sstp_text, flags=re.IGNORECASE))
        sstp_port_m = re.search(r"\.opengw\.net:(\d+)", sstp_text, flags=re.IGNORECASE)
        sstp_port = int(sstp_port_m.group(1)) if sstp_port_m else (ssl_tcp_port or ovpn_tcp_port or 443)

        # Column 9: Score
        score_text = re.sub(r"[^0-9]", "", re.sub(r"<[^>]+>", "", tds[9]))
        score = int(score_text) if score_text.isdigit() else 100000

        if not (has_ovpn or has_sslvpn or has_sstp or has_l2tp):
            continue

        results.append(
            {
                "HostName": host_name or f"vpn-{ip.replace('.', '-')}",
                "IP": ip,
                "Score": str(score),
                "Ping": str(ping),
                "Speed": str(speed_bps),
                "CountryLong": country_long or country_short,
                "CountryShort": country_short,
                "NumVpnSessions": str(sessions),
                "has_openvpn": has_ovpn,
                "ovpn_tcp_port": ovpn_tcp_port,
                "ovpn_udp_port": ovpn_udp_port,
                "has_sslvpn": has_sslvpn,
                "ssl_tcp_port": ssl_tcp_port,
                "has_sstp": has_sstp,
                "sstp_port": sstp_port,
                "has_l2tp": has_l2tp,
            }
        )
        if max_rows is not None and len(results) >= max_rows:
            break

    return results
