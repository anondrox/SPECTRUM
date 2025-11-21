#!/usr/bin/env python3
\"\"\"SPECTRUM PRO - Premium Domain Technology & CVE Intelligence Scanner
Designed by: anondrox

Compared to a simple tech-fingerprint tool, SPECTRUM PRO focuses on:
- Deeper multi-path scanning per domain
- Multi-signal technology detection (headers, cookies, HTML, JS, paths)
- CVE intelligence per detected framework (best-effort)
- Simple risk scoring per asset (0–10)
- Optional history logging for later diffing / reporting

Usage:
    python spectrum_pro.py domains.txt
    python spectrum_pro.py domains.txt --json
    python spectrum_pro.py domains.txt --no-cve
    python spectrum_pro.py domains.txt --max-cves 20
    python spectrum_pro.py domains.txt --history-file history.jsonl
    python spectrum_pro.py domains.txt --top-risks 5
\"\"\"

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

# ---------------------------------------------------------------------------
# BANNER
# ---------------------------------------------------------------------------

BANNER = 


S P E C T R U M   P R O  •  Premium Domain Tech & CVE Intel\\033[0m
                     Designed by: anondrox\\033[0m



def print_banner() -> None:
    print(BANNER)


# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 7
USER_AGENT = "SPECTRUM-PRO/1.0 (+internal-audit)"
CVE_API_BASE = "https://cve.circl.lu/api"
DEFAULT_MAX_CVES = 50

# Paths to probe per domain (relative)
SCAN_PATHS = [
    "/",               # main page
    "/robots.txt",
    "/sitemap.xml",
    "/manifest.json",
    "/wp-json/",
    "/wp-login.php",
    "/admin",
    "/login",
    "/xmlrpc.php",
    "/favicon.ico",
]

# How many script files to fetch per domain (to avoid going crazy)
MAX_JS_ASSETS = 8

# Map detected framework names -> (vendor, product) for CVE lookup.
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
# DATA STRUCTURES
# ---------------------------------------------------------------------------

@dataclass
class PageResult:
    url: str
    status_code: Optional[int] = None
    error: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class TechFinding:
    languages: set = field(default_factory=set)
    frameworks: set = field(default_factory=set)
    platforms: set = field(default_factory=set)
    cdn: set = field(default_factory=set)
    hosting: set = field(default_factory=set)
    exposed_endpoints: set = field(default_factory=set)

    def add_lang(self, x: str) -> None:
        self.languages.add(x)

    def add_fw(self, x: str) -> None:
        self.frameworks.add(x)

    def add_platform(self, x: str) -> None:
        self.platforms.add(x)

    def add_cdn(self, x: str) -> None:
        self.cdn.add(x)

    def add_hosting(self, x: str) -> None:
        self.hosting.add(x)

    def add_exposed(self, x: str) -> None:
        self.exposed_endpoints.add(x)


# ---------------------------------------------------------------------------
# HTTP HELPERS
# ---------------------------------------------------------------------------

def http_get(url: str,
             timeout: int = REQUEST_TIMEOUT,
             headers: Optional[Dict[str, str]] = None) -> requests.Response:
    hdr = {"User-Agent": USER_AGENT}
    if headers:
        hdr.update(headers)
    return requests.get(url, timeout=timeout, headers=hdr, allow_redirects=True)


def normalize_url(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    parsed = urlparse(line)
    if parsed.scheme:
        return line
    return f"https://{line}"


# ---------------------------------------------------------------------------
# FINGERPRINT RULES
# ---------------------------------------------------------------------------

HEADER_LANG_HINTS = [
    (re.compile(r"php", re.I), "PHP"),
    (re.compile(r"asp\.net|iis", re.I), ".NET"),
    (re.compile(r"node\.js|express", re.I), "Node.js"),
    (re.compile(r"python|wsgi|gunicorn", re.I), "Python"),
    (re.compile(r"ruby|passenger|unicorn", re.I), "Ruby"),
    (re.compile(r"java|tomcat|jetty|jboss|wildfly", re.I), "Java"),
]

HEADER_FW_HINTS = [
    (re.compile(r"wordpress", re.I), "WordPress"),
    (re.compile(r"drupal", re.I), "Drupal"),
    (re.compile(r"joomla", re.I), "Joomla"),
    (re.compile(r"magento", re.I), "Magento"),
    (re.compile(r"laravel", re.I), "Laravel"),
    (re.compile(r"symfony", re.I), "Symfony"),
    (re.compile(r"django", re.I), "Django"),
    (re.compile(r"flask", re.I), "Flask"),
    (re.compile(r"next\.js", re.I), "Next.js"),
    (re.compile(r"nuxt", re.I), "Nuxt.js"),
    (re.compile(r"spring", re.I), "Spring"),
]

COOKIE_HINTS = [
    (re.compile(r"wordpress_", re.I), "WordPress"),
    (re.compile(r"wp-settings-", re.I), "WordPress"),
    (re.compile(r"laravel_session", re.I), "Laravel"),
    (re.compile(r"ci_session", re.I), "CodeIgniter"),
    (re.compile(r"symfony", re.I), "Symfony"),
    (re.compile(r"drupal", re.I), "Drupal"),
]

HTML_HINTS = [
    # CMS
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"drupal\.settings|drupal\.js", re.I), "Drupal"),
    (re.compile(r'content="joomla!', re.I), "Joomla"),
    (re.compile(r"mage\.cookies|magento", re.I), "Magento"),
    # Frontend frameworks
    (re.compile(r"react-dom", re.I), "React"),
    (re.compile(r"__REACT_DEVTOOLS_GLOBAL_HOOK__", re.I), "React"),
    (re.compile(r"vue\.js", re.I), "Vue.js"),
    (re.compile(r"nuxt\.js", re.I), "Nuxt.js"),
    (re.compile(r"angular\.js|ng-version=", re.I), "Angular"),
    (re.compile(r"svelte", re.I), "Svelte"),
    # UI frameworks
    (re.compile(r"bootstrap(\.min)?\.css", re.I), "Bootstrap"),
    (re.compile(r"tailwind(\.min)?\.css", re.I), "Tailwind CSS"),
    (re.compile(r"bulma\.min\.css", re.I), "Bulma"),
    # Commerce / SaaS
    (re.compile(r"cdn\.shopify\.com", re.I), "Shopify"),
    (re.compile(r"squarespace\.com", re.I), "Squarespace"),
    (re.compile(r"wixstatic\.com", re.I), "Wix"),
    # CDNs
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
]

JS_HINTS = [
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"Nuxt\.js", re.I), "Nuxt.js"),
    (re.compile(r"ReactDOM\.render", re.I), "React"),
    (re.compile(r"angular\.module\(", re.I), "Angular"),
    (re.compile(r"SvelteComponent", re.I), "Svelte"),
    (re.compile(r"jQuery", re.I), "jQuery"),
    (re.compile(r"\.use\(VueRouter\)", re.I), "Vue.js"),
]

PATH_HINTS = [
    (re.compile(r"/wp-login\.php", re.I), "WordPress"),
    (re.compile(r"/wp-json/", re.I), "WordPress"),
    (re.compile(r"/user/login", re.I), "Drupal"),
    (re.compile(r"/administrator", re.I), "Joomla"),
    (re.compile(r"/index\.php/admin", re.I), "Magento"),
]

EXPOSED_ENDPOINT_PATTERNS = [
    re.compile(r"/wp-login\.php", re.I),
    re.compile(r"/wp-admin", re.I),
    re.compile(r"/xmlrpc\.php", re.I),
    re.compile(r"/admin", re.I),
    re.compile(r"/login", re.I),
]

# Favicon hash fingerprints (SHA1 of favicon bytes) - extend over time.
FAVICON_SHA1: Dict[str, str] = {
    # Example:
    # "c4ca4238a0b923820dcc509a6f75849b": "ExampleTech"
}


# ---------------------------------------------------------------------------
# DETECTION FUNCTIONS
# ---------------------------------------------------------------------------

def analyze_headers(headers: Dict[str, str], findings: TechFinding) -> None:
    server = headers.get("Server", "") or ""
    xpb = headers.get("X-Powered-By", "") or ""
    combo = f"{server} {xpb}"

    for pattern, lang in HEADER_LANG_HINTS:
        if pattern.search(combo):
            findings.add_lang(lang)

    for pattern, fw in HEADER_FW_HINTS:
        if pattern.search(combo):
            findings.add_fw(fw)

    # CDN hints
    if re.search(r"cloudflare", combo, re.I):
        findings.add_cdn("Cloudflare")
    if re.search(r"akamai", combo, re.I):
        findings.add_cdn("Akamai")
    if re.search(r"fastly", combo, re.I):
        findings.add_cdn("Fastly")


def analyze_cookies(headers: Dict[str, str], findings: TechFinding) -> None:
    cookies = headers.get("Set-Cookie", "") or ""
    for pattern, fw in COOKIE_HINTS:
        if pattern.search(cookies):
            findings.add_fw(fw)


def analyze_html(body: str, findings: TechFinding) -> None:
    for pattern, fw in HTML_HINTS:
        if pattern.search(body):
            findings.add_fw(fw)

    # meta generator tag
    generator_match = re.search(
        r'<meta\s+name=["\\\']generator["\\\']\s+content=["\\\']([^"\\\']+)["\\\']',
        body,
        re.I,
    )
    if generator_match:
        findings.add_platform(f"Generator: {generator_match.group(1)}")


def extract_script_urls(body: str, base_url: str) -> List[str]:
    urls: List[str] = []
    for m in re.finditer(r'<script[^>]+src=["\\\']([^"\\\']+)["\\\']', body, re.I):
        src = m.group(1)
        full = urljoin(base_url, src)
        urls.append(full)
    seen = set()
    unique: List[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique[:MAX_JS_ASSETS]


def analyze_js(js_text: str, findings: TechFinding) -> None:
    for pattern, fw in JS_HINTS:
        if pattern.search(js_text):
            findings.add_fw(fw)


def analyze_path(url: str, findings: TechFinding) -> None:
    path = urlparse(url).path
    for pattern, fw in PATH_HINTS:
        if pattern.search(path):
            findings.add_fw(fw)
    for pat in EXPOSED_ENDPOINT_PATTERNS:
        if pat.search(path):
            findings.add_exposed(path)


def analyze_favicon(content: bytes, findings: TechFinding) -> None:
    if not content:
        return
    sha1 = hashlib.sha1(content).hexdigest()
    tech = FAVICON_SHA1.get(sha1)
    if tech:
        findings.add_platform(f"Favicon: {tech}")


# ---------------------------------------------------------------------------
# CVE CLIENT
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
                for entry in data:
                    cid = entry.get("id")
                    if cid:
                        ids.append(cid)
            ids = list(dict.fromkeys(ids))[: self.max_cves]
            self._cache[key] = ids
            return ids
        except Exception:
            self._cache[key] = []
            return []

    def lookup_frameworks(self, frameworks: List[str]) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        for fw in frameworks:
            mapping = FRAMEWORK_TO_VENDOR_PRODUCT.get(fw)
            if not mapping:
                result[fw] = []
                continue
            vendor, product = mapping
            result[fw] = self.fetch_for_vendor_product(vendor, product)
        return result


# ---------------------------------------------------------------------------
# RISK SCORING
# ---------------------------------------------------------------------------

def compute_risk(findings: TechFinding, cves: Dict[str, List[str]]) -> Tuple[float, List[str]]:
    \"\"\"Very simple heuristic risk model (0–10).
    This is not a formal vulnerability score, just a prioritization helper.
    \"\"\"
    score = 0.0
    factors: List[str] = []

    # If we have any frameworks at all
    if findings.frameworks:
        score += 1.0
        factors.append("Application frameworks detected")

    # Exposed endpoints (wp-login, /admin, /login, xmlrpc, etc.)
    if findings.exposed_endpoints:
        score += 2.0
        factors.append(f"Exposed auth/admin endpoints: {', '.join(sorted(findings.exposed_endpoints))}")

    # CDNs/WAF: if none detected, small bump (potentially less protection)
    if not findings.cdn:
        score += 1.0
        factors.append("No CDN/WAF fingerprint detected (best-effort)")

    # CVE volume per framework
    total_cves = sum(len(v) for v in cves.values())
    if total_cves > 0:
        if total_cves <= 20:
            score += 1.0
            factors.append(f"Limited CVE history for detected frameworks (~{total_cves})")
        elif total_cves <= 100:
            score += 2.0
            factors.append(f"Moderate CVE history for detected frameworks (~{total_cves})")
        else:
            score += 3.0
            factors.append(f"Large CVE history for detected frameworks (>{total_cves})")

    # Language-based hints (purely heuristic)
    if "PHP" in findings.languages:
        score += 1.0
        factors.append("PHP application (often internet-facing CMS / legacy apps)")
    if "Java" in findings.languages:
        score += 0.5
        factors.append("Java application (complex frameworks, potential historical CVEs)")
    if ".NET" in findings.languages:
        score += 0.5
        factors.append(".NET stack (may have legacy components)")

    # Cap score between 0 and 10
    if score < 0:
        score = 0.0
    if score > 10:
        score = 10.0

    return round(score, 1), factors


# ---------------------------------------------------------------------------
# PER DOMAIN SCAN
# ---------------------------------------------------------------------------

def scan_domain(domain: str, cve_client: Optional[CVEClient]) -> Dict[str, Any]:
    base_url = normalize_url(domain)
    findings = TechFinding()
    page_results: List[PageResult] = []

    session = requests.Session()

    # Fetch multiple paths
    for rel in SCAN_PATHS:
        full_url = urljoin(base_url, rel)
        res = PageResult(url=full_url)
        try:
            r = session.get(full_url, headers={"User-Agent": USER_AGENT},
                            timeout=REQUEST_TIMEOUT, allow_redirects=True)
            res.status_code = r.status_code
            res.headers = dict(r.headers)
            res.content_type = r.headers.get("Content-Type", "")
            analyze_path(full_url, findings)

            if "favicon.ico" in full_url and r.ok:
                analyze_favicon(r.content, findings)

            ct_lower = (res.content_type or "").lower()
            if ct_lower.startswith("text/") or "json" in ct_lower:
                res.body = r.text[:1_000_000]
        except Exception as e:
            res.error = str(e)

        page_results.append(res)

        # Header & cookie analysis
        if res.headers:
            analyze_headers(res.headers, findings)
            analyze_cookies(res.headers, findings)

        # HTML body analysis
        if res.body and "text/html" in (res.content_type or "").lower():
            analyze_html(res.body, findings)

    # JS asset scanning (from main page body if available)
    js_urls: List[str] = []
    if page_results and page_results[0].body:
        js_urls = extract_script_urls(page_results[0].body, page_results[0].url)
        for js_url in js_urls:
            try:
                jr = session.get(js_url, headers={"User-Agent": USER_AGENT},
                                 timeout=REQUEST_TIMEOUT)
                if "javascript" in jr.headers.get("Content-Type", "").lower() or js_url.endswith(".js"):
                    analyze_js(jr.text[:500_000], findings)
            except Exception:
                continue

    # CVE lookup
    if cve_client is not None and findings.frameworks:
        cve_map: Dict[str, List[str]] = cve_client.lookup_frameworks(sorted(findings.frameworks))
    else:
        cve_map = {fw: [] for fw in findings.frameworks}

    # Risk scoring
    risk_score, risk_factors = compute_risk(findings, cve_map)

    # Build result
    result: Dict[str, Any] = {
        "input": domain,
        "normalized_base": base_url,
        "paths_scanned": [p.url for p in page_results],
        "findings": {
            "languages": sorted(findings.languages),
            "frameworks": sorted(findings.frameworks),
            "platforms": sorted(findings.platforms),
            "cdn": sorted(findings.cdn),
            "hosting": sorted(findings.hosting),
            "exposed_endpoints": sorted(findings.exposed_endpoints),
        },
        "pages": [
            {
                "url": p.url,
                "status_code": p.status_code,
                "error": p.error,
                "headers": {k: v for k, v in p.headers.items()
                            if k in ("Server", "X-Powered-By", "Set-Cookie", "Content-Type")},
            }
            for p in page_results
        ],
        "js_assets_scanned": js_urls,
        "cves": cve_map,
        "risk": {
            "score": risk_score,
            "factors": risk_factors,
        },
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
    }

    return result


# ---------------------------------------------------------------------------
# OUTPUT
# ---------------------------------------------------------------------------

def print_tree(domain_result: Dict[str, Any]) -> None:
    print(domain_result["input"])
    print("├── normalized_base:", domain_result.get("normalized_base"))
    print("├── risk_score:", domain_result.get("risk", {}).get("score"))
    print("├── risk_factors:")
    factors = domain_result.get("risk", {}).get("factors") or []
    if factors:
        for f in factors:
            print("│   ├──", f)
    else:
        print("│   └── (none)")

    print("├── paths_scanned:")
    for p in domain_result.get("paths_scanned", []):
        print("│   ├──", p)

    findings = domain_result.get("findings", {})
    print("├── languages:", ", ".join(findings.get("languages", [])) or "(none)")

    print("├── frameworks:")
    for fw in findings.get("frameworks", []) or ["(none)"]:
        print("│   ├──", fw)

    print("├── platforms:")
    for pf in findings.get("platforms", []) or ["(none)"]:
        print("│   ├──", pf)

    print("├── cdn:", ", ".join(findings.get("cdn", [])) or "(none)")
    print("├── hosting:", ", ".join(findings.get("hosting", [])) or "(none)")

    print("├── exposed_endpoints:")
    for ep in findings.get("exposed_endpoints", []) or ["(none)"]:
        print("│   ├──", ep)

    print("├── cves:")
    cves = domain_result.get("cves") or {}
    if cves:
        for fw, ids in cves.items():
            print("│   ├──", fw)
            if ids:
                for cid in ids:
                    print("│   │   ├──", cid)
            else:
                print("│   │   └── (no CVEs or not mapped)")
    else:
        print("│   └── (none)")

    print("└── pages:")
    for page in domain_result.get("pages", []):
        print("    ├──", page["url"])
        print("    │   ├── status_code:", page.get("status_code"))
        if page.get("error"):
            print("    │   ├── error:", page["error"])
        print("    │   └── headers:")
        for k, v in page.get("headers", {}).items():
            print(f"    │       ├── {k}: {v}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_domains(path: str) -> List[str]:
    p = Path(path)
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    out: List[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SPECTRUM PRO - Premium Wappalyzer-style tech & CVE scanner"
    )
    parser.add_argument("domains_file", help="Path to text file with domains/URLs (one per line).")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of tree.")
    parser.add_argument("--no-cve", action="store_true", help="Disable CVE lookup.")
    parser.add_argument("--max-cves", type=int, default=DEFAULT_MAX_CVES,
                        help=f"Max CVEs per framework (default {DEFAULT_MAX_CVES}).")
    parser.add_argument("--history-file", type=str,
                        help="Optional path to append scan results as JSONL for history.")
    parser.add_argument("--top-risks", type=int,
                        help="Show only the top N most risky assets (by score).")
    return parser.parse_args(argv)


def save_history(history_path: str, results: List[Dict[str, Any]]) -> None:
    path = Path(history_path)
    with path.open("a", encoding="utf-8") as f:
        for item in results:
            f.write(json.dumps(item) + "\n")


def main(argv: Optional[List[str]] = None) -> None:
    print_banner()
    args = parse_args(argv)

    domains = load_domains(args.domains_file)
    cve_client: Optional[CVEClient] = None if args.no_cve else CVEClient(args.max_cves)

    results: List[Dict[str, Any]] = []
    for d in domains:
        res = scan_domain(d, cve_client)
        results.append(res)

    # Optional history logging
    if args.history_file:
        save_history(args.history_file, results)

    # Optional sorting by risk for top-risks view
    if args.top_risks:
        results = sorted(results,
                         key=lambda r: (r.get("risk", {}).get("score") or 0.0),
                         reverse=True)
        results = results[: args.top_risks]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for i, res in enumerate(results):
            print_tree(res)
            if i != len(results) - 1:
                print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
