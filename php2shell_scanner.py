#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP2Shell Defensive Exposure Auditor (CVE-2026-109618 & CVE-2026-109619)
Author / Handle: @absholi7ly
Purpose: Non-destructive, defensive security auditing tool to evaluate whether
         PHP web endpoints or local PHP runtimes are exposed to CVE-2026-109618
         (GHSA-w8hw-w9fx-j79w) and CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp).

Legal Notice: For authorized defensive auditing and compliance verification only.
              This tool performs passive header/version analysis, optional benign
              RFC 1867 multipart policy checks, and local INI configuration audits.
              It contains NO exploit payloads or memory-corruption inputs.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

TOOL_NAME = "PHP2Shell Exposure Auditor"
TOOL_VERSION = "1.0.0"
AUTHOR_TAG = "@absholi7ly"

# Official patched versions released on October 21, 2026
PATCHED_VERSIONS: Dict[Tuple[int, int], Tuple[int, int, int]] = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}

# Distro backport markers in version banners
BACKPORT_PATTERNS = [
    r"ubuntu.*8948",
    r"deb13u",
    r"DSA-6574",
    r"USN-8948",
]


class Colors:
    """ANSI color codes for formatted terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def disable(cls) -> None:
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""


@dataclass
class TargetScanResult:
    """Structured result for a single scanned target URL."""

    input_target: str
    normalized_url: str
    reachable: bool = False
    http_status: int = 0
    response_time_ms: float = 0.0
    server_header: str = "Not Disclosed"
    x_powered_by: str = "Not Disclosed"
    detected_php_version: str = "Unknown (Hidden)"
    sapi_fingerprint: str = "Unknown"
    sapi_risk_level: str = "Unknown"
    waf_or_proxy: str = "None Detected"
    session_cookie_present: bool = False
    multipart_policy: str = "Not Tested"
    exposure_status: str = "UNKNOWN"
    severity_score: str = "N/A"
    cve_2026_109618_status: str = "Unverified (Banner Hidden)"
    cve_2026_109619_status: str = "Unverified (Banner Hidden)"
    remediation_advice: str = ""
    notes: List[str] = field(default_factory=list)
    timestamp_utc: str = ""


def print_banner(no_color: bool = False) -> None:
    """Prints the formatted CLI banner with the tool name and @absholi7ly."""
    if no_color or not sys.stdout.isatty():
        Colors.disable()

    c = Colors
    banner = f"""
{c.CYAN}{c.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗        ║
║   ██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║        ║
║   ██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║        ║
║   ██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║        ║
║   ██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗   ║
║   ╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ║
║                                                                              ║
║          {c.WHITE}PHP2Shell Defensive Exposure Auditor & Readiness Scanner{c.CYAN}            ║
║                  {c.YELLOW}CVE-2026-109618 & CVE-2026-109619 (CVSS 9.2){c.CYAN}                ║
║                                 {c.MAGENTA}{AUTHOR_TAG}{c.CYAN}                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{c.RESET}
"""
    print(banner)


def normalize_url(raw_target: str, default_scheme: str = "https") -> List[str]:
    """
    Normalizes any target string (domain, IP, IP:port, full URL with path/query)
    into candidate URLs to test.
    """
    target = raw_target.strip()
    if not target or target.startswith("#"):
        return []

    if re.match(r"^https?://", target, re.IGNORECASE):
        parsed = urllib.parse.urlsplit(target)
        path = parsed.path if parsed.path else "/"
        normalized = urllib.parse.urlunsplit(
            (parsed.scheme.lower(), parsed.netloc, path, parsed.query, "")
        )
        return [normalized]

    # If no scheme is provided, try https first then http (or http first for local IPs)
    is_local = target.startswith(("127.", "localhost", "10.", "192.168.", "172."))
    schemes = ["http", "https"] if is_local else [default_scheme, "http" if default_scheme == "https" else "https"]
    candidates = []
    for scheme in schemes:
        cand = f"{scheme}://{target}"
        parsed = urllib.parse.urlsplit(cand)
        path = parsed.path if parsed.path else "/"
        candidates.append(
            urllib.parse.urlunsplit((scheme, parsed.netloc, path, parsed.query, ""))
        )
    return candidates


def parse_php_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts PHP semantic version (major, minor, patch, raw_string) from
    X-Powered-By, Server headers, or telemetry output.
    """
    match = re.search(r"PHP/(\d+)\.(\d+)\.(\d+)([A-Za-z0-9._~+-]*)", text, re.IGNORECASE)
    if not match:
        return None
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    suffix = match.group(4) or ""
    raw_ver = f"{major}.{minor}.{patch}{suffix}"
    return major, minor, patch, raw_ver


def classify_php_version(
    major: int, minor: int, patch: int, raw_ver: str
) -> Tuple[str, str, str, str, str]:
    """
    Evaluates a detected PHP version against the official CVE-2026-109618 and
    CVE-2026-109619 patch matrix (8.5.12, 8.4.27, 8.3.36, 8.2.35).
    Returns: (exposure_status, severity_score, cve_18_status, cve_19_status, advice)
    """
    for pat in BACKPORT_PATTERNS:
        if re.search(pat, raw_ver, re.IGNORECASE):
            return (
                "PATCHED (BACKPORT)",
                "0.0 (Safe)",
                "Patched via Distro Backport",
                "Patched via Distro Backport",
                "Distribution security backport detected. Verify worker restart.",
            )

    branch = (major, minor)
    ver_tuple = (major, minor, patch)

    if (major == 5 and minor < 4) or major < 5:
        return (
            "LEGACY_EOL",
            "High (EOL)",
            "Predates 5.4.0 upload_progress (Still EOL)",
            "Predates 5.4.0 upload_progress (Still EOL)",
            "Upgrade immediately to supported PHP 8.2+.",
        )

    if branch in PATCHED_VERSIONS:
        fixed_tuple = PATCHED_VERSIONS[branch]
        fixed_str = f"{fixed_tuple[0]}.{fixed_tuple[1]}.{fixed_tuple[2]}"
        if ver_tuple >= fixed_tuple:
            return (
                "PATCHED",
                "0.0 (Safe)",
                f"Patched (>= {fixed_str})",
                f"Patched (>= {fixed_str})",
                f"Running patched release {raw_ver}. Ensure all web workers were restarted.",
            )
        return (
            "VULNERABLE",
            "9.2 (Critical)",
            f"VULNERABLE (< {fixed_str})",
            f"VULNERABLE (< {fixed_str})",
            f"CRITICAL: Upgrade PHP {major}.{minor} branch to {fixed_str} immediately and restart workers.",
        )

    if major > 8 or (major == 8 and minor > 5):
        return (
            "PATCHED",
            "0.0 (Safe)",
            "Patched (Newer Branch)",
            "Patched (Newer Branch)",
            "Version is newer than the affected release window.",
        )

    # EOL Affected Branches: PHP 5.4 - 8.1
    if branch in [(8, 1), (8, 0), (7, 4)]:
        return (
            "VULNERABLE (EOL)",
            "9.2 (Critical - EOL)",
            "VULNERABLE (EOL Branch - Needs Source/Distro Backport)",
            "VULNERABLE (EOL Branch - Needs Source/Distro Backport)",
            f"CRITICAL: PHP {major}.{minor} is EOL. Apply official PHP source backports / distro LTS packages or upgrade to PHP 8.2.35+ / 8.4.27+.",
        )

    return (
        "VULNERABLE (EOL)",
        "9.2 (Critical - EOL)",
        "VULNERABLE (Unsupported Legacy PHP 5.4 - 7.3)",
        "VULNERABLE (Unsupported Legacy PHP 5.4 - 7.3)",
        f"CRITICAL: PHP {raw_ver} is affected and receives no upstream patches. Migrate to PHP 8.2.35+ / 8.4.27+ immediately.",
    )


def fingerprint_sapi_and_waf(headers: Dict[str, str]) -> Tuple[str, str, str]:
    """
    Infers the likely PHP SAPI, its SAPI risk tier per GHSA-w8hw-w9fx-j79w,
    and any edge WAF/reverse proxy from HTTP response headers.
    """
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    via = headers.get("via", "")
    cf_ray = headers.get("cf-ray", "")

    waf_list = []
    if cf_ray or "cloudflare" in server.lower():
        waf_list.append("Cloudflare WAF/CDN")
    if "akamai" in server.lower() or "akamai" in via.lower():
        waf_list.append("Akamai")
    if "imperva" in server.lower() or headers.get("x-iinfo"):
        waf_list.append("Imperva")
    if "awselb" in server.lower() or "cloudfront" in via.lower():
        waf_list.append("AWS CloudFront/ALB")
    waf_str = ", ".join(waf_list) if waf_list else "None Detected"

    combined = f"{server} {powered}".lower()
    if "frankenphp" in combined:
        return (
            "FrankenPHP",
            "CRITICAL (Pre-Script Unconditional RSHUTDOWN)",
            waf_str,
        )
    if "apache" in server.lower() and "php/" in server.lower():
        return (
            "Apache mod_php (apache2handler)",
            "CRITICAL (Highest Risk - Validated Pre-Script RCE)",
            waf_str,
        )
    if "litespeed" in combined:
        return (
            "LiteSpeed (LSAPI)",
            "HIGH (FPM-Model Worker Reuse)",
            waf_str,
        )
    if "nginx" in server.lower() or "fpm" in combined:
        return (
            "PHP-FPM (behind Nginx/FastCGI)",
            "HIGH (Validated in CVE-2026-109619 / Susceptible in 109618)",
            waf_str,
        )
    if "apache" in server.lower():
        return (
            "Apache (mod_php or proxy_fcgi/PHP-FPM)",
            "HIGH-CRITICAL (Verify apachectl -M for mod_php vs proxy_fcgi)",
            waf_str,
        )
    return ("Undetermined SAPI", "HIGH (If PHP is active behind proxy)", waf_str)


def perform_benign_multipart_check(
    url: str,
    timeout: float,
    user_agent: str,
    custom_headers: Dict[str, str],
    ctx: ssl.SSLContext,
    opener: urllib.request.OpenerDirector,
) -> Tuple[str, List[str]]:
    """
    Sends a strictly benign, standard 1-field multipart/form-data request
    (with zero OOM amplification or exploit content) to check whether the
    web server/WAF blocks multipart POST requests or accepts them.
    """
    boundary = "----DefensiveAuditBoundary9921"
    body_lines = [
        f"--{boundary}",
        'Content-Disposition: form-data; name="audit_ping"',
        "",
        "safe_check",
        f"--{boundary}--",
        "",
    ]
    body_bytes = "\r\n".join(body_lines).encode("utf-8")

    headers = {
        "User-Agent": user_agent,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Accept": "*/*",
    }
    headers.update(custom_headers)

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
    notes = []
    try:
        with opener.open(req, timeout=timeout) as resp:
            code = resp.getcode()
            resp_headers = {k.lower(): v for k, v in resp.info().items()}
            set_cookie = resp_headers.get("set-cookie", "")
            if "phpsessid" in set_cookie.lower():
                notes.append("Target issued PHPSESSID on POST response.")
            return f"Accepted (HTTP {code} - Multipart reaches backend)", notes
    except urllib.error.HTTPError as e:
        if e.code in (403, 405, 406, 413, 415, 503):
            return f"Blocked/Restricted by Edge/Server (HTTP {e.code})", notes
        return f"Reachable (HTTP {e.code})", notes
    except Exception as ex:
        return f"Connection Error ({type(ex).__name__})", notes


def scan_single_target(
    raw_target: str,
    timeout: float = 8.0,
    verify_ssl: bool = False,
    check_multipart: bool = False,
    user_agent: str = f"{TOOL_NAME}/{TOOL_VERSION} ({AUTHOR_TAG})",
    custom_headers: Optional[Dict[str, str]] = None,
    proxy: Optional[str] = None,
) -> TargetScanResult:
    """Scans a single target URL safely and returns a structured TargetScanResult."""
    custom_headers = custom_headers or {}
    candidates = normalize_url(raw_target)
    timestamp_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if not candidates:
        return TargetScanResult(
            input_target=raw_target,
            normalized_url=raw_target,
            exposure_status="INVALID_URL",
            remediation_advice="Provide a valid URL, domain, or IP address.",
            timestamp_utc=timestamp_now,
        )

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    handlers: List[urllib.request.BaseHandler] = [
        urllib.request.HTTPSHandler(context=ctx)
    ]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)

    last_error = ""
    for cand_url in candidates:
        req_headers = {"User-Agent": user_agent, "Accept": "*/*"}
        req_headers.update(custom_headers)
        req = urllib.request.Request(cand_url, headers=req_headers, method="GET")

        t0 = time.monotonic()
        try:
            with opener.open(req, timeout=timeout) as resp:
                elapsed_ms = round((time.monotonic() - t0) * 1000.0, 1)
                status_code = resp.getcode()
                raw_headers = {k.lower(): v for k, v in resp.info().items()}
                body_sample = resp.read(4096).decode("utf-8", errors="ignore")
                return _evaluate_response(
                    raw_target,
                    cand_url,
                    status_code,
                    elapsed_ms,
                    raw_headers,
                    body_sample,
                    check_multipart,
                    timeout,
                    user_agent,
                    custom_headers,
                    ctx,
                    opener,
                    timestamp_now,
                )
        except urllib.error.HTTPError as e:
            elapsed_ms = round((time.monotonic() - t0) * 1000.0, 1)
            raw_headers = (
                {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            )
            body_sample = ""
            try:
                body_sample = e.read(4096).decode("utf-8", errors="ignore")
            except Exception:
                pass
            return _evaluate_response(
                raw_target,
                cand_url,
                e.code,
                elapsed_ms,
                raw_headers,
                body_sample,
                check_multipart,
                timeout,
                user_agent,
                custom_headers,
                ctx,
                opener,
                timestamp_now,
            )
        except Exception as ex:
            last_error = f"{type(ex).__name__}: {ex}"

    return TargetScanResult(
        input_target=raw_target,
        normalized_url=candidates[0],
        reachable=False,
        exposure_status="UNREACHABLE",
        remediation_advice=f"Target unreachable ({last_error}). Verify network connectivity or URL.",
        timestamp_utc=timestamp_now,
    )


def _evaluate_response(
    raw_target: str,
    cand_url: str,
    status_code: int,
    elapsed_ms: float,
    raw_headers: Dict[str, str],
    body_sample: str,
    check_multipart: bool,
    timeout: float,
    user_agent: str,
    custom_headers: Dict[str, str],
    ctx: ssl.SSLContext,
    opener: urllib.request.OpenerDirector,
    timestamp_now: str,
) -> TargetScanResult:
    """Evaluates HTTP response headers, telemetry output, and version banners."""
    server_hdr = raw_headers.get("server", "Not Disclosed")
    powered_hdr = raw_headers.get("x-powered-by", "Not Disclosed")
    set_cookie = raw_headers.get("set-cookie", "")
    has_phpsessid = "phpsessid" in set_cookie.lower()

    sapi_name, sapi_risk, waf_str = fingerprint_sapi_and_waf(raw_headers)
    notes: List[str] = []

    if has_phpsessid:
        notes.append("Active PHPSESSID session cookie observed in HTTP response.")

    # Check if the target URL is a diagnostic probe (like verify_env.php / audit_probe.php)
    probe_ver_match = re.search(
        r"PHP[_\s]Version\s*:\s*([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9._~+-]*)",
        body_sample,
        re.IGNORECASE,
    )
    combined_version_source = f"{powered_hdr} {server_hdr}"
    if probe_ver_match:
        combined_version_source += f" PHP/{probe_ver_match.group(1)}"
        notes.append("Extracted exact runtime version from diagnostic endpoint output.")

    parsed_ver = parse_php_version(combined_version_source)
    if parsed_ver:
        major, minor, patch, raw_ver = parsed_ver
        exp_status, sev_score, cve18, cve19, advice = classify_php_version(
            major, minor, patch, raw_ver
        )
        detected_ver_str = raw_ver
    else:
        detected_ver_str = "Hidden (expose_php=Off or Non-PHP)"
        if has_phpsessid or ".php" in cand_url.lower() or "php" in combined_version_source.lower():
            exp_status = "POTENTIALLY_EXPOSED (VERSION_HIDDEN)"
            sev_score = "9.2 (If Unpatched)"
            cve18 = "Requires Local/SAPI Verification (Banner Hidden)"
            cve19 = "Requires Local/SAPI Verification (Banner Hidden)"
            advice = (
                "PHP runtime detected, but version banner is hidden (expose_php=Off). "
                "Run `php2shell_scanner.py --local-audit` on the server or verify via web SAPI "
                "that PHP is >= 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35."
            )
        else:
            exp_status = "UNKNOWN (NO_PHP_INDICATORS)"
            sev_score = "Unknown"
            cve18 = "No PHP Banner Detected"
            cve19 = "No PHP Banner Detected"
            advice = (
                "No explicit PHP indicators found in HTTP headers. If this host runs PHP behind "
                "a reverse proxy, verify the backend PHP runtime directly."
            )

    multipart_status = "Skipped (Use --check-multipart)"
    if check_multipart:
        mp_res, mp_notes = perform_benign_multipart_check(
            cand_url, timeout, user_agent, custom_headers, ctx, opener
        )
        multipart_status = mp_res
        notes.extend(mp_notes)

    return TargetScanResult(
        input_target=raw_target,
        normalized_url=cand_url,
        reachable=True,
        http_status=status_code,
        response_time_ms=elapsed_ms,
        server_header=server_hdr,
        x_powered_by=powered_hdr,
        detected_php_version=detected_ver_str,
        sapi_fingerprint=sapi_name,
        sapi_risk_level=sapi_risk,
        waf_or_proxy=waf_str,
        session_cookie_present=has_phpsessid,
        multipart_policy=multipart_status,
        exposure_status=exp_status,
        severity_score=sev_score,
        cve_2026_109618_status=cve18,
        cve_2026_109619_status=cve19,
        remediation_advice=advice,
        notes=notes,
        timestamp_utc=timestamp_now,
    )


def run_local_runtime_audit() -> Dict[str, object]:
    """
    Audits the local machine's installed PHP CLI/FPM binaries and INI settings
    for CVE-2026-109618 and CVE-2026-109619 readiness.
    """
    c = Colors
    print(f"{c.CYAN}{c.BOLD}[*] Running Local PHP Runtime & Configuration Audit...{c.RESET}\n")
    report: Dict[str, object] = {"binaries": [], "timestamp_utc": datetime.now(timezone.utc).isoformat()}

    php_bins = []
    for candidate in ["php", "php-fpm", "php8.5", "php8.4", "php8.3", "php8.2", "php8.1", "php8.0", "php7.4"]:
        path = shutil.which(candidate)
        if path and path not in php_bins:
            php_bins.append(path)

    if not php_bins:
        print(f"{c.YELLOW}[!] No local PHP binary found in PATH on this machine.{c.RESET}\n")
        return report

    for bin_path in php_bins:
        try:
            ver_out = subprocess.check_output([bin_path, "-v"], stderr=subprocess.STDOUT, text=True, timeout=5)
            first_line = ver_out.splitlines()[0] if ver_out else ""
            ver_match = re.search(r"PHP\s+(\d+)\.(\d+)\.(\d+)([A-Za-z0-9._~+-]*)", first_line)
            ini_info = {}
            if "php-fpm" not in os.path.basename(bin_path):
                eval_code = (
                    'echo json_encode(['
                    '"version" => PHP_VERSION,'
                    '"Loaded_INI" => php_ini_loaded_file(),'
                    '"memory_limit" => ini_get("memory_limit"),'
                    '"post_max_size" => ini_get("post_max_size"),'
                    '"upload_progress" => ini_get("session.upload_progress.enabled"),'
                    '"fatal_backtraces" => ini_get("fatal_error_backtraces")'
                    ']);'
                )
                raw_json = subprocess.check_output([bin_path, "-r", eval_code], stderr=subprocess.DEVNULL, text=True, timeout=5)
                ini_info = json.loads(raw_json)

            if ver_match:
                maj, min_, pat = int(ver_match.group(1)), int(ver_match.group(2)), int(ver_match.group(3))
                raw_v = f"{maj}.{min_}.{pat}{ver_match.group(4) or ''}"
                status, score, c18, c19, adv = classify_php_version(maj, min_, pat, raw_v)
            else:
                raw_v, status, score, c18, c19, adv = ("Unknown", "UNKNOWN", "N/A", "Unknown", "Unknown", "Check manually")

            color = c.GREEN if "PATCHED" in status else c.RED
            print(f"  {c.BOLD}Binary Path           :{c.RESET} {bin_path}")
            print(f"  {c.BOLD}Detected Version      :{c.RESET} {raw_v}")
            print(f"  {c.BOLD}Exposure Verdict      :{c.RESET} {color}{c.BOLD}{status}{c.RESET} (CVSS: {score})")
            if ini_info:
                print(f"  {c.BOLD}Loaded php.ini        :{c.RESET} {ini_info.get('Loaded_INI') or '(none)'}")
                print(f"  {c.BOLD}memory_limit          :{c.RESET} {ini_info.get('memory_limit')}")
                print(f"  {c.BOLD}post_max_size         :{c.RESET} {ini_info.get('post_max_size')}")
                print(f"  {c.BOLD}upload_progress.enab  :{c.RESET} {ini_info.get('upload_progress')}")
                print(f"  {c.BOLD}fatal_error_backtraces:{c.RESET} {ini_info.get('fatal_backtraces')}")
            print(f"  {c.BOLD}Action Required       :{c.RESET} {adv}")
            print(f"  {c.DIM}" + ("─" * 72) + f"{c.RESET}")

            report["binaries"].append({
                "binary": bin_path,
                "version": raw_v,
                "status": status,
                "ini": ini_info,
                "advice": adv,
            })
        except Exception as e:
            print(f"  {c.RED}[!] Failed to inspect {bin_path}: {e}{c.RESET}")

    print(
        f"\n{c.YELLOW}[!] Reminder:{c.RESET} CLI `php -v` may differ from the binary loaded by Apache (`mod_php`) "
        f"or `php-fpm` pools. Always verify your active web SAPI as well.\n"
    )
    return report


def status_badge(status: str) -> str:
    """Formats the exposure status with ANSI color coding."""
    c = Colors
    if status.startswith("PATCHED"):
        return f"{c.GREEN}{c.BOLD}[✓ {status}]{c.RESET}"
    if status.startswith("VULNERABLE"):
        return f"{c.RED}{c.BOLD}[! {status}]{c.RESET}"
    if "POTENTIALLY_EXPOSED" in status:
        return f"{c.YELLOW}{c.BOLD}[? {status}]{c.RESET}"
    return f"{c.BLUE}{c.BOLD}[i {status}]{c.RESET}"


def print_formatted_results(results: List[TargetScanResult]) -> None:
    """Prints detailed per-target cards and a summary table."""
    c = Colors
    print(f"{c.CYAN}{c.BOLD}══════════════════════════ DETAILED TARGET AUDIT RESULTS ═════════════════════════{c.RESET}\n")

    for idx, res in enumerate(results, start=1):
        print(f"{c.BOLD}[Target #{idx}] {c.WHITE}{res.normalized_url}{c.RESET} (Input: {res.input_target})")
        print(f"  ├─ {c.BOLD}Exposure Status       :{c.RESET} {status_badge(res.exposure_status)}")
        if not res.reachable:
            print(f"  └─ {c.BOLD}Diagnostic Note       :{c.RESET} {c.RED}{res.remediation_advice}{c.RESET}\n")
            continue

        print(f"  ├─ {c.BOLD}HTTP Status & Latency :{c.RESET} HTTP {res.http_status} ({res.response_time_ms} ms)")
        print(f"  ├─ {c.BOLD}Detected PHP Version  :{c.RESET} {c.CYAN}{res.detected_php_version}{c.RESET}")
        print(f"  ├─ {c.BOLD}Server / X-Powered-By :{c.RESET} Server: {res.server_header} | X-Powered-By: {res.x_powered_by}")
        print(f"  ├─ {c.BOLD}SAPI & Risk Profile   :{c.RESET} {res.sapi_fingerprint} -> {res.sapi_risk_level}")
        print(f"  ├─ {c.BOLD}WAF / Edge Proxy      :{c.RESET} {res.waf_or_proxy}")
        print(f"  ├─ {c.BOLD}Multipart POST Policy :{c.RESET} {res.multipart_policy}")
        print(f"  ├─ {c.BOLD}CVE-2026-109618 (OOM) :{c.RESET} {res.cve_2026_109618_status}")
        print(f"  ├─ {c.BOLD}CVE-2026-109619 (UAF) :{c.RESET} {res.cve_2026_109619_status}")
        if res.notes:
            print(f"  ├─ {c.BOLD}Telemetry Observations:{c.RESET} {'; '.join(res.notes)}")
        print(f"  └─ {c.BOLD}Remediation Guidance  :{c.RESET} {res.remediation_advice}\n")

    # Summary Statistics Table
    total = len(results)
    vuln = sum(1 for r in results if r.exposure_status.startswith("VULNERABLE"))
    patched = sum(1 for r in results if r.exposure_status.startswith("PATCHED"))
    potential = sum(1 for r in results if "POTENTIALLY_EXPOSED" in r.exposure_status)
    other = total - vuln - patched - potential

    print(f"{c.CYAN}{c.BOLD}════════════════════════════════ SCAN SUMMARY TABLE ══════════════════════════════{c.RESET}")
    print(f"  {c.BOLD}Total Targets Scanned     :{c.RESET} {total}")
    print(f"  {c.RED}{c.BOLD}Confirmed Vulnerable      :{c.RESET} {vuln}")
    print(f"  {c.YELLOW}{c.BOLD}Potentially Exposed       :{c.RESET} {potential} (PHP detected, version banner hidden)")
    print(f"  {c.GREEN}{c.BOLD}Confirmed Patched / Safe  :{c.RESET} {patched}")
    print(f"  {c.BLUE}{c.BOLD}Unknown / Unreachable     :{c.RESET} {other}")
    print(f"{c.CYAN}{c.BOLD}══════════════════════════════════════════════════════════════════════════════════{c.RESET}\n")


def export_results(results: List[TargetScanResult], output_path: str) -> None:
    """Exports scan results to JSON, CSV, or Markdown based on file extension."""
    ext = os.path.splitext(output_path)[1].lower()
    data_dicts = [asdict(r) for r in results]

    if ext == ".json":
        payload = {
            "tool": TOOL_NAME,
            "author": AUTHOR_TAG,
            "version": TOOL_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "results": data_dicts,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
    elif ext == ".csv":
        if data_dicts:
            fieldnames = list(data_dicts[0].keys())
            with open(output_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for row in data_dicts:
                    row_copy = dict(row)
                    row_copy["notes"] = "; ".join(row_copy.get("notes", []))
                    writer.writerow(row_copy)
    else:
        # Default to Markdown report
        lines = [
            f"# {TOOL_NAME} — Scan Report ({AUTHOR_TAG})",
            f"**Generated (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "| Target URL | HTTP | PHP Version | SAPI | Exposure Status | Multipart Policy |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for r in results:
            lines.append(
                f"| `{r.normalized_url}` | {r.http_status} | `{r.detected_php_version}` | {r.sapi_fingerprint} | **{r.exposure_status}** | {r.multipart_policy} |"
            )
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    print(f"{Colors.GREEN}[✓] Exported scan report to: {output_path}{Colors.RESET}\n")


def collect_targets(args: argparse.Namespace) -> List[str]:
    """Collects and deduplicates targets from CLI arguments and target files."""
    raw_targets: List[str] = []
    if args.url:
        for item in args.url:
            # Support comma-separated lists passed to -u as well
            for sub in item.split(","):
                if sub.strip():
                    raw_targets.append(sub.strip())

    if args.list:
        if not os.path.isfile(args.list):
            print(f"{Colors.RED}[!] Error: Target list file not found: {args.list}{Colors.RESET}", file=sys.stderr)
            sys.exit(2)
        with open(args.list, "r", encoding="utf-8") as f:
            for line in f:
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("#"):
                    raw_targets.append(cleaned)

    # Deduplicate while preserving order
    seen = set()
    unique_targets = []
    for t in raw_targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)
    return unique_targets


def build_arg_parser() -> argparse.ArgumentParser:
    """Builds the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="php2shell_scanner.py",
        description=(
            f"{TOOL_NAME} ({AUTHOR_TAG}) — Defensive Vulnerability & Exposure Scanner "
            "for PHP Core RCEs CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) & CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  1. Scan a single target URL or domain:
     python3 php2shell_scanner.py -u https://example.com

  2. Scan multiple targets directly from the command line:
     python3 php2shell_scanner.py -u https://site1.example.com http://127.0.0.1:8080/index.php

  3. Scan a list of targets from a file with 10 threads and benign multipart policy check:
     python3 php2shell_scanner.py -l targets.txt -t 10 --check-multipart -o report.json

  4. Audit local server PHP binaries and php.ini configuration directly:
     python3 php2shell_scanner.py --local-audit
""",
    )

    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument(
        "-u",
        "--url",
        nargs="+",
        metavar="URL",
        help="One or more target URLs, domains, or IP:Port endpoints to scan (supports comma-separated or space-separated targets).",
    )
    target_group.add_argument(
        "-l",
        "--list",
        metavar="FILE",
        help="Path to a text file containing target URLs/domains (one per line).",
    )
    target_group.add_argument(
        "--local-audit",
        action="store_true",
        help="Audit local PHP binaries and php.ini directives (memory_limit, session.upload_progress.enabled, fatal_error_backtraces).",
    )

    scan_group = parser.add_argument_group("Scan & Request Options")
    scan_group.add_argument(
        "--check-multipart",
        action="store_true",
        help="Send a benign 1-field multipart/form-data request to check whether edge WAF/server rules block or accept multipart POST traffic.",
    )
    scan_group.add_argument(
        "-t",
        "--threads",
        type=int,
        default=5,
        metavar="N",
        help="Number of concurrent scanning threads for multi-target scans (default: 5).",
    )
    scan_group.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        metavar="SEC",
        help="HTTP request timeout in seconds (default: 8.0).",
    )
    scan_group.add_argument(
        "-H",
        "--header",
        action="append",
        metavar="'Name: Value'",
        help="Custom HTTP header to include in requests (can be specified multiple times).",
    )
    scan_group.add_argument(
        "--proxy",
        metavar="PROXY_URL",
        help="HTTP/HTTPS proxy URL (e.g., http://127.0.0.1:8080).",
    )
    scan_group.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Enforce strict TLS/SSL certificate verification (disabled by default for IP/lab targets).",
    )

    out_group = parser.add_argument_group("Output & Reporting Options")
    out_group.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Save scan results to a file (.json, .csv, or .md).",
    )
    out_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output.",
    )

    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    print_banner(no_color=args.no_color)

    if not args.url and not args.list and not args.local_audit:
        parser.print_help()
        sys.exit(0)

    if args.local_audit:
        run_local_runtime_audit()

    targets = collect_targets(args)
    if not targets:
        sys.exit(0)

    custom_headers: Dict[str, str] = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()

    print(
        f"{Colors.CYAN}[*] Loaded {len(targets)} unique target(s) | Threads: {args.threads} | "
        f"Timeout: {args.timeout}s | Multipart Check: {'ON' if args.check_multipart else 'OFF'}{Colors.RESET}\n"
    )

    results: List[TargetScanResult] = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
        future_to_target = {
            executor.submit(
                scan_single_target,
                t,
                args.timeout,
                args.verify_ssl,
                args.check_multipart,
                f"{TOOL_NAME}/{TOOL_VERSION} ({AUTHOR_TAG})",
                custom_headers,
                args.proxy,
            ): t
            for t in targets
        }
        for future in as_completed(future_to_target):
            results.append(future.result())

    # Sort results to match input order
    order_map = {t: i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order_map.get(r.input_target, 999999))

    print_formatted_results(results)

    if args.output:
        export_results(results, args.output)


if __name__ == "__main__":
    main()