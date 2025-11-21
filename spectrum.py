#!/usr/bin/env python3
"""SPECTRUM - Domain Technology & CVE Intelligence Scanner
Designed by: anondrox

Usage:
    python spectrum.py domains.txt
    python spectrum.py domains.txt --json
    python spectrum.py domains.txt --no-cve
    python spectrum.py domains.txt --max-cves 20
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = """
S P E C T R U M  •  Domain Technology & CVE Intelligence Scanner
                    Designed by: anondrox
"""


def print_banner() -> None:
    print(BANNER)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 7
USER_AGENT = "SPECTRUM/1.0 (+internal-audit)"
CVE_API_BASE = "https://cve.circl.lu/api"
DEFAULT_MAX_CVES = 50

FRAMEWORK_TO_VENDOR_PRODUCT: Dict[str, Tuple[str, str]] = {
    "WordPress": ("wordpress", "wordpress"),
    "Drupal": ("drupal", "drupal"),
    "Joomla": ("joomla", "joomla"),
    "Magento": ("magento", "magento"),
    "Laravel": ("laravel", "laravel"),
    "Symfony": ("symfony", "symfony"),
    "CodeIgniter": ("ellislab", "codeigniter"),
}


# ---------------------------------------------------------------------------
# HTTP Helpers
# ---------------------------------------------------------------------------

def http_get(url: str,
             timeout: int = REQUEST_TIMEOUT,
             headers: Optional[Dict[str, str]] = None) -> requests.Response:
    hdr = {"User-Agent": USER_AGENT}
    if headers:
        hdr.update(headers)
    return requests.get(url, timeout=timeout, headers=hdr)


def normalize_url(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    parsed = urlparse(line)
    if parsed.scheme:
        return line
    return f"https://{line}"


def fetch_url(url: str) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        resp = http_get(url)
        return resp, None
    except Exception as e:
        if url.startswith("https://"):
            fallback = url.replace("https://", "http://", 1)
            try:
                resp = http_get(fallback)
                return resp, None
            except Exception as e2:
                return None, f"https failed: {e}; http failed: {e2}"
        return None, str(e)


# ---------------------------------------------------------------------------
# Detection Logic
# ---------------------------------------------------------------------------

def detect_from_headers(headers: Dict[str, str]) -> Tuple[Optional[str], List[str]]:
    server = headers.get("Server", "") or ""
    xpb = headers.get("X-Powered-By", "") or ""
    combo = (server + " " + xpb).lower()

    language: Optional[str] = None
    frameworks: set[str] = set()

    if "php" in combo:
        language = "PHP"
    elif "asp.net" in combo or "iis" in combo:
        language = ".NET"
    elif "node.js" in combo or "express" in combo:
        language = "Node.js"
    elif "python" in combo or "wsgi" in combo:
        language = "Python"
    elif "ruby" in combo or "rails" in combo:
        language = "Ruby"
    elif any(t in combo for t in ("java", "tomcat", "jetty", "jboss")):
        language = "Java"

    if "wordpress" in combo:
        frameworks.add("WordPress")
    if "laravel" in combo:
        frameworks.add("Laravel")
    if "django" in combo:
        frameworks.add("Django")
    if "flask" in combo:
        frameworks.add("Flask")
    if "spring" in combo:
        frameworks.add("Spring")

    return language, sorted(frameworks)


def detect_from_cookies(headers: Dict[str, str]) -> List[str]:
    cookies = (headers.get("Set-Cookie", "") or "").lower()
    frameworks: set[str] = set()
    if "wordpress_" in cookies:
        frameworks.add("WordPress")
    if "laravel_session" in cookies:
        frameworks.add("Laravel")
    if "drupal" in cookies:
        frameworks.add("Drupal")
    if "symfony" in cookies:
        frameworks.add("Symfony")
    if "ci_session" in cookies:
        frameworks.add("CodeIgniter")
    return sorted(frameworks)


def detect_from_html(html: str) -> List[str]:
    lower = html.lower()
    frameworks: set[str] = set()

    if "wp-content" in lower or "wp-includes" in lower:
        frameworks.add("WordPress")
    if "drupal.settings" in lower:
        frameworks.add("Drupal")
    if 'content="joomla!' in lower:
        frameworks.add("Joomla")
    if "magento" in lower:
        frameworks.add("Magento")

    return sorted(frameworks)


# ---------------------------------------------------------------------------
# CVE Lookups
# ---------------------------------------------------------------------------

class CVEClient:
    def __init__(self, max_cves: int = DEFAULT_MAX_CVES) -> None:
        self.max_cves = max_cves
        self._cache: Dict[Tuple[str, str], List[str]] = {}

    def fetch_for_vendor_product(self, vendor: str, product: str) -> List[str]:
        key = (vendor, product)
        if key in self._cache:
            return self._cache[key]

        url = f"{CVE_API_BASE}/search/{vendor}/{product}"
        try:
            resp = http_get(url)
            if resp.status_code != 200:
                self._cache[key] = []
                return []
            data = resp.json()
            ids: List[str] = []
            if isinstance(data, list):
                for item in data:
                    cid = item.get("id")
                    if cid:
                        ids.append(cid)
            ids = list(dict.fromkeys(ids))[: self.max_cves]
            self._cache[key] = ids
            return ids
        except Exception:
            self._cache[key] = []
            return []

    def lookup_frameworks(self, frameworks: List[str]) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for fw in frameworks:
            mapping = FRAMEWORK_TO_VENDOR_PRODUCT.get(fw)
            if not mapping:
                out[fw] = []
                continue
            vendor, product = mapping
            out[fw] = self.fetch_for_vendor_product(vendor, product)
        return out


# ---------------------------------------------------------------------------
# Domain Scan
# ---------------------------------------------------------------------------

def scan_domain(url: str, cve_client: Optional[CVEClient]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "input": url,
        "final_url": None,
        "status_code": None,
        "error": None,
        "headers": {},
        "detected_frameworks": [],
        "detected_language": None,
        "cves": {},
    }

    resp, err = fetch_url(url)
    if err is not None:
        result["error"] = err
        return result

    result["final_url"] = resp.url
    result["status_code"] = resp.status_code

    interesting_headers = ("Server", "X-Powered-By", "Set-Cookie")
    headers = {k: v for k, v in resp.headers.items() if k in interesting_headers}
    result["headers"] = headers

    lang_h, fw_h = detect_from_headers(headers)
    fw_c = detect_from_cookies(headers)

    fw_html: List[str] = []
    content_type = resp.headers.get("Content-Type", "")
    if content_type and "text/html" in content_type.lower():
        try:
            fw_html = detect_from_html(resp.text[:500_000])
        except Exception:
            fw_html = []

    frameworks = sorted(set(fw_h) | set(fw_c) | set(fw_html))
    result["detected_frameworks"] = frameworks
    result["detected_language"] = lang_h

    if cve_client is not None:
        result["cves"] = cve_client.lookup_frameworks(frameworks)
    else:
        result["cves"] = {fw: [] for fw in frameworks}

    return result


# ---------------------------------------------------------------------------
# Output Rendering
# ---------------------------------------------------------------------------

def print_tree(item: Dict[str, Any]) -> None:
    print(item["input"])
    print("├── final_url:", item.get("final_url"))
    if item.get("error"):
        print("├── status: ERROR")
        print("│   └──", item["error"])
        print("└── (no further data)")
        return

    print("├── status_code:", item.get("status_code"))

    print("├── headers")
    headers = item.get("headers") or {}
    if headers:
        for k, v in headers.items():
            print(f"│   ├── {k}: {v}")
    else:
        print("│   └── (none)")

    print("├── detected_language:", item.get("detected_language") or "(unknown)")

    print("├── detected_frameworks")
    frameworks = item.get("detected_frameworks") or []
    if frameworks:
        for fw in frameworks:
            print(f"│   ├── {fw}")
    else:
        print("│   └── (none)")

    print("└── cves")
    cves = item.get("cves") or {}
    if cves:
        for fw, ids in cves.items():
            print(f"    ├── {fw}")
            if ids:
                for cid in ids:
                    print(f"    │   ├── {cid}")
            else:
                print("    │   └── (none)")
    else:
        print("    └── (none)")


# ---------------------------------------------------------------------------
# CLI Helpers
# ---------------------------------------------------------------------------

def load_domains(path: str) -> List[str]:
    p = Path(path)
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    urls: List[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        url = normalize_url(line)
        if url:
            urls.append(url)
    return urls


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SPECTRUM - Domain Technology & CVE Intelligence Scanner"
    )
    parser.add_argument("domains_file", help="Path to a text file with domains/URLs (one per line).")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of tree.")
    parser.add_argument("--no-cve", action="store_true", help="Disable CVE lookup (faster).")
    parser.add_argument("--max-cves", type=int, default=DEFAULT_MAX_CVES,
                        help=f"Max CVEs per framework (default: {DEFAULT_MAX_CVES}).")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    print_banner()
    args = parse_args(argv)

    domains = load_domains(args.domains_file)
    cve_client: Optional[CVEClient] = None if args.no_cve else CVEClient(args.max_cves)

    results = [scan_domain(d, cve_client) for d in domains]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for idx, item in enumerate(results):
            print_tree(item)
            if idx != len(results) - 1:
                print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
