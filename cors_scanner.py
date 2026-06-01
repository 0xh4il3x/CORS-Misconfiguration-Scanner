#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           CORS MISCONFIGURATION SECURITY SCANNER                ║
║           Fast · Modular · Professional                         ║
╚══════════════════════════════════════════════════════════════════╝

Author  : Haileamlak & Claude 
Version : 1.0.0
Purpose : Detect CORS misconfigurations in web applications
Usage   : python cors_scanner.py -u https://example.com
          python cors_scanner.py -f targets.txt --threads 20
"""

import argparse
import concurrent.futures
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
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

SEVERITY_COLOR = {
    Severity.CRITICAL : C.RED + C.BOLD,
    Severity.HIGH     : C.RED,
    Severity.MEDIUM   : C.YELLOW,
    Severity.LOW      : C.CYAN,
    Severity.INFO     : C.WHITE,
}

@dataclass
class Finding:
    check_name  : str
    severity    : Severity
    description : str
    evidence    : str
    remediation : str
    url         : str

@dataclass
class ScanResult:
    url      : str
    findings : list[Finding] = field(default_factory=list)
    errors   : list[str]     = field(default_factory=list)
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
        "User-Agent": "Mozilla/5.0 (CORS-Scanner/2.0; Security Research)",
        "Accept"    : "*/*",
    })
    session.verify  = verify_ssl
    session.timeout = timeout
    return session

# ──────────────────────────────────────────────
#  Individual CORS Checks
# ──────────────────────────────────────────────
class CORSChecks:
    """All CORS misconfiguration detection logic lives here."""

    # ── 1. Wildcard origin ────────────────────
    @staticmethod
    def wildcard_origin(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.get(url, headers={"Origin": "https://evil.com"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                return Finding(
                    check_name  = "Wildcard ACAO",
                    severity    = Severity.MEDIUM,
                    description = "Server returns Access-Control-Allow-Origin: * allowing any origin to read the response.",
                    evidence    = f"Access-Control-Allow-Origin: {acao}",
                    remediation = "Restrict ACAO to a specific trusted origin instead of *.",
                    url         = url,
                )
        except Exception:
            pass
        return None

    # ── 2. Reflected origin ───────────────────
    @staticmethod
    def reflected_origin(url: str, session: requests.Session) -> Optional[Finding]:
        evil = "https://evil-attacker.com"
        try:
            r = session.get(url, headers={"Origin": evil})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == evil:
                sev = Severity.CRITICAL if acac.lower() == "true" else Severity.HIGH
                return Finding(
                    check_name  = "Reflected Origin" + (" + Credentials" if acac.lower() == "true" else ""),
                    severity    = sev,
                    description = (
                        "Server blindly reflects any supplied Origin header back. "
                        + ("Combined with Allow-Credentials: true, authenticated requests can be hijacked."
                           if acac.lower() == "true" else "")
                    ),
                    evidence    = f"Origin sent: {evil}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    remediation = "Validate Origin against a strict whitelist; never reflect arbitrary origins.",
                    url         = url,
                )
        except Exception:
            pass
        return None

    # ── 3. Null origin ────────────────────────
    @staticmethod
    def null_origin(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.get(url, headers={"Origin": "null"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "null":
                sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                return Finding(
                    check_name  = "Null Origin Allowed",
                    severity    = sev,
                    description = "Server trusts the 'null' origin, which can be spoofed via sandboxed iframes.",
                    evidence    = f"Access-Control-Allow-Origin: {acao}",
                    remediation = "Never whitelist the 'null' origin in production.",
                    url         = url,
                )
        except Exception:
            pass
        return None

    # ── 4. Prefix/suffix bypass ───────────────
    @staticmethod
    def prefix_suffix_bypass(url: str, session: requests.Session) -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        base = parsed.netloc  # e.g. api.example.com

        # Derive the root domain (handles subdomains)
        parts = base.split(".")
        root  = ".".join(parts[-2:]) if len(parts) >= 2 else base

        test_cases = [
            (f"https://evil{root}",         "prefix bypass — attacker prefix before domain"),
            (f"https://{root}.evil.com",     "suffix bypass — domain used as subdomain of attacker"),
            (f"https://{base}.evil.com",     "full-host suffix bypass"),
            (f"https://evil.{root}",         "subdomain injection"),
            (f"http://{root}",               "HTTP downgrade (http vs https)"),
        ]

        for origin, reason in test_cases:
            try:
                r = session.get(url, headers={"Origin": origin})
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                if acao == origin:
                    findings.append(Finding(
                        check_name  = f"Origin Bypass ({reason})",
                        severity    = Severity.HIGH,
                        description = f"Weak origin regex allows bypass via: {origin}",
                        evidence    = f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                        remediation = "Use exact-match string comparison, not substring/regex matching, for origin validation.",
                        url         = url,
                    ))
            except Exception:
                pass
        return findings

    # ── 5. Trusted subdomain wildcard ─────────
    @staticmethod
    def subdomain_wildcard(url: str, session: requests.Session) -> Optional[Finding]:
        parsed = urlparse(url)
        parts  = parsed.netloc.split(".")
        root   = ".".join(parts[-2:]) if len(parts) >= 2 else parsed.netloc
        origin = f"https://xss.{root}"
        try:
            r = session.get(url, headers={"Origin": origin})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if acao == origin:
                return Finding(
                    check_name  = "Subdomain Wildcard Trust",
                    severity    = Severity.MEDIUM,
                    description = f"Any subdomain of {root} is trusted. An XSS on any subdomain leads to CORS bypass.",
                    evidence    = f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                    remediation = "Whitelist only specific known subdomains, not the entire *.domain.com space.",
                    url         = url,
                )
        except Exception:
            pass
        return None

    # ── 6. HTTP method exposure ───────────────
    @staticmethod
    def dangerous_methods(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.options(url, headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "Authorization",
            })
            acam = r.headers.get("Access-Control-Allow-Methods", "")
            dangerous = [m for m in ["PUT", "DELETE", "PATCH", "TRACE"] if m in acam.upper()]
            if dangerous:
                return Finding(
                    check_name  = "Dangerous Methods Allowed",
                    severity    = Severity.MEDIUM,
                    description = f"Preflight exposes sensitive HTTP methods: {', '.join(dangerous)}",
                    evidence    = f"Access-Control-Allow-Methods: {acam}",
                    remediation = "Restrict allowed methods to only those required by the API.",
                    url         = url,
                )
        except Exception:
            pass
        return None

    # ── 7. Credentials without explicit origin ─
    @staticmethod
    def credentials_without_specific_origin(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.get(url, headers={"Origin": "https://legitimate.example.com"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acac.lower() == "true" and acao == "*":
                return Finding(
                    check_name  = "Credentials + Wildcard",
                    severity    = Severity.CRITICAL,
                    description = "Allow-Credentials: true with wildcard origin is an invalid but dangerous configuration.",
                    evidence    = f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    remediation = "Never combine wildcard origin with Allow-Credentials: true.",
                    url         = url,
                )
        except Exception:
            pass
        return None

    # ── 8. Sensitive headers exposed ──────────
    @staticmethod
    def sensitive_headers_exposed(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.get(url, headers={"Origin": "https://evil.com"})
            aceh = r.headers.get("Access-Control-Expose-Headers", "")
            sensitive = [h for h in ["Authorization", "Cookie", "X-Api-Key", "X-Auth-Token",
                                      "Set-Cookie", "WWW-Authenticate"]
                         if h.lower() in aceh.lower()]
            if sensitive:
                return Finding(
                    check_name  = "Sensitive Headers Exposed",
                    severity    = Severity.MEDIUM,
                    description = f"Sensitive response headers are exposed to cross-origin scripts: {', '.join(sensitive)}",
                    evidence    = f"Access-Control-Expose-Headers: {aceh}",
                    remediation = "Only expose headers that are necessary and non-sensitive.",
                    url         = url,
                )
        except Exception:
            pass
        return None

    # ── 9. Missing Vary header ─────────────────
    @staticmethod
    def missing_vary_header(url: str, session: requests.Session) -> Optional[Finding]:
        try:
            r = session.get(url, headers={"Origin": "https://example.com"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            vary = r.headers.get("Vary", "")
            if acao and acao != "*" and "origin" not in vary.lower():
                return Finding(
                    check_name  = "Missing Vary: Origin",
                    severity    = Severity.LOW,
                    description = "ACAO is dynamic but 'Vary: Origin' is absent, risking cache poisoning attacks.",
                    evidence    = f"Access-Control-Allow-Origin: {acao}\nVary: {vary or '(not set)'}",
                    remediation = "Add 'Vary: Origin' when serving dynamic ACAO values to prevent cache poisoning.",
                    url         = url,
                )
        except Exception:
            pass
        return None

    # ── 10. CORS on sensitive endpoints ───────
    @staticmethod
    def sensitive_endpoint_cors(url: str, session: requests.Session) -> Optional[Finding]:
        sensitive_paths = ["/api/", "/admin", "/account", "/user", "/auth",
                           "/login", "/token", "/graphql", "/v1/", "/v2/"]
        parsed = urlparse(url)
        path   = parsed.path.lower()
        for sp in sensitive_paths:
            if sp in path:
                try:
                    r = session.get(url, headers={"Origin": "https://evil.com"})
                    acao = r.headers.get("Access-Control-Allow-Origin", "")
                    if acao:
                        return Finding(
                            check_name  = "CORS on Sensitive Endpoint",
                            severity    = Severity.INFO,
                            description = f"CORS headers present on a potentially sensitive path ({path}).",
                            evidence    = f"Access-Control-Allow-Origin: {acao}",
                            remediation = "Ensure sensitive endpoints have strict CORS policies.",
                            url         = url,
                        )
                except Exception:
                    pass
        return None

# ──────────────────────────────────────────────
#  Scanner Engine
# ──────────────────────────────────────────────
class CORSScanner:
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout    = timeout
        self.verify_ssl = verify_ssl

    def scan(self, url: str) -> ScanResult:
        result  = ScanResult(url=url)
        start   = time.time()
        session = make_session(self.timeout, self.verify_ssl)
        checks  = CORSChecks()

        # Normalise URL
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            result.url = url

        single_checks = [
            checks.wildcard_origin,
            checks.reflected_origin,
            checks.null_origin,
            checks.subdomain_wildcard,
            checks.dangerous_methods,
            checks.credentials_without_specific_origin,
            checks.sensitive_headers_exposed,
            checks.missing_vary_header,
            checks.sensitive_endpoint_cors,
        ]

        for check in single_checks:
            try:
                finding = check(url, session)
                if finding:
                    result.findings.append(finding)
            except Exception as e:
                result.errors.append(f"{check.__name__}: {e}")

        # Multi-return check
        try:
            for f in checks.prefix_suffix_bypass(url, session):
                result.findings.append(f)
        except Exception as e:
            result.errors.append(f"prefix_suffix_bypass: {e}")

        result.duration = round(time.time() - start, 2)
        session.close()
        return result

# ──────────────────────────────────────────────
#  Output / Reporting
# ──────────────────────────────────────────────
SEVERITY_ICON = {
    Severity.CRITICAL : "💀",
    Severity.HIGH     : "🔴",
    Severity.MEDIUM   : "🟡",
    Severity.LOW      : "🔵",
    Severity.INFO     : "ℹ️ ",
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
{C.RESET}{C.DIM}  CORS Misconfiguration Security Scanner  v2.0.0{C.RESET}
""")

def severity_label(sev: Severity) -> str:
    col = SEVERITY_COLOR.get(sev, "")
    return f"{col}[{sev.value:8s}]{C.RESET}"

def print_result(result: ScanResult, verbose: bool = False):
    icon = "✅" if not result.findings else "⚠️ "
    hsev = result.highest_severity
    col  = SEVERITY_COLOR.get(hsev, C.GREEN) if hsev else C.GREEN

    print(f"\n{bold('Target:')} {result.url}")
    print(f"{bold('Duration:')} {result.duration}s  |  "
          f"{bold('Findings:')} {len(result.findings)}  |  "
          f"{bold('Status:')} {col}{'VULNERABLE' if result.vulnerable else 'CLEAN'}{C.RESET}")

    if not result.findings:
        print(f"  {green('No CORS issues detected.')}")

    for i, f in enumerate(result.findings, 1):
        icon = SEVERITY_ICON.get(f.severity, "•")
        print(f"\n  {icon} {severity_label(f.severity)} {bold(f.check_name)}")
        print(f"     {dim('Description :')} {f.description}")
        if verbose:
            for line in f.evidence.splitlines():
                print(f"     {dim('Evidence    :')} {cyan(line)}")
            print(f"     {dim('Remediation :')} {yellow(f.remediation)}")

    if result.errors and verbose:
        print(f"\n  {yellow('Warnings/Errors:')}")
        for e in result.errors:
            print(f"    {dim('•')} {e}")

    print(f"  {'─'*60}")

def print_summary(results: list[ScanResult]):
    total      = len(results)
    vulnerable = sum(1 for r in results if r.vulnerable)
    clean      = total - vulnerable
    by_sev     = {s: 0 for s in Severity}
    for r in results:
        for f in r.findings:
            by_sev[f.severity] += 1

    print(f"\n{bold('═'*64)}")
    print(f"{bold('  SCAN SUMMARY')}")
    print(f"{bold('═'*64)}")
    print(f"  Targets scanned : {total}")
    print(f"  Vulnerable      : {red(str(vulnerable)) if vulnerable else green('0')}")
    print(f"  Clean           : {green(str(clean))}")
    print(f"\n  Findings by severity:")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = by_sev[sev]
        col   = SEVERITY_COLOR.get(sev, "")
        bar   = "█" * min(count, 40)
        print(f"    {col}{sev.value:8s}{C.RESET}  {bar} {count}")
    print(f"{bold('═'*64)}\n")

def save_json_report(results: list[ScanResult], path: str):
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_targets": len(results),
        "vulnerable_count": sum(1 for r in results if r.vulnerable),
        "results": [
            {
                "url"      : r.url,
                "vulnerable": r.vulnerable,
                "duration" : r.duration,
                "findings" : [
                    {
                        "check"      : f.check_name,
                        "severity"   : f.severity.value,
                        "description": f.description,
                        "evidence"   : f.evidence,
                        "remediation": f.remediation,
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

def save_text_report(results: list[ScanResult], path: str):
    lines = []
    lines.append("CORS MISCONFIGURATION SCAN REPORT")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z\n")
    for r in results:
        lines.append(f"URL: {r.url}")
        lines.append(f"Status: {'VULNERABLE' if r.vulnerable else 'CLEAN'}")
        lines.append(f"Duration: {r.duration}s")
        for f in r.findings:
            lines.append(f"\n  [{f.severity.value}] {f.check_name}")
            lines.append(f"  Description : {f.description}")
            lines.append(f"  Evidence    : {f.evidence}")
            lines.append(f"  Remediation : {f.remediation}")
        lines.append("-" * 60)
    with open(path, "w") as fp:
        fp.write("\n".join(lines))
    print(f"{green('✔')} Text report saved → {bold(path)}")

# ──────────────────────────────────────────────
#  CLI Entry Point
# ──────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        prog="cors_scanner",
        description="Professional CORS Misconfiguration Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cors_scanner.py -u https://api.example.com
  python cors_scanner.py -u https://example.com/api/v1/users --verbose
  python cors_scanner.py -f targets.txt --threads 20 --output report.json
  python cors_scanner.py -u https://example.com --timeout 15 --no-ssl-verify
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url",  help="Single target URL")
    group.add_argument("-f", "--file", help="File with one URL per line")

    parser.add_argument("--threads",       type=int,  default=10,   help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout",       type=int,  default=10,   help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-ssl-verify", action="store_true",     help="Disable SSL certificate verification")
    parser.add_argument("--verbose","-v",  action="store_true",     help="Show evidence and remediation details")
    parser.add_argument("--output", "-o",                           help="Save JSON report to file")
    parser.add_argument("--output-txt",                             help="Save plain-text report to file")
    parser.add_argument("--quiet",  "-q",  action="store_true",     help="Only print vulnerable targets")
    return parser.parse_args()


def main():
    args = parse_args()
    print_banner()

    # ── Build target list ──────────────────────
    targets: list[str] = []
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
    print(f"{bold('Verbose  :')} {args.verbose}\n")
    print(f"{'─'*64}")

    scanner = CORSScanner(timeout=args.timeout, verify_ssl=not args.no_ssl_verify)
    results : list[ScanResult] = []

    # ── Concurrent scanning ────────────────────
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        future_to_url = {pool.submit(scanner.scan, t): t for t in targets}
        for future in concurrent.futures.as_completed(future_to_url):
            result = future.result()
            results.append(result)
            if args.quiet and not result.vulnerable:
                continue
            print_result(result, verbose=args.verbose)

    # ── Summary ────────────────────────────────
    print_summary(results)

    # ── Reports ────────────────────────────────
    if args.output:
        save_json_report(results, args.output)
    if args.output_txt:
        save_text_report(results, args.output_txt)

    # ── Exit code — useful in CI/CD ────────────
    sys.exit(1 if any(r.vulnerable for r in results) else 0)


if __name__ == "__main__":
    main()
