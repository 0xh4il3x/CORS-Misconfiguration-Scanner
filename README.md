# CORS Misconfiguration Scanner

Professional CORS misconfiguration scanner for authorized security testing and red-team engagements.

This tool is designed to identify misconfigured CORS policies in web applications and APIs by testing common abuse patterns, dynamic origin validation weaknesses, credential exposure, and preflight abuse.

It is intended for legitimate security research, internal validation, and authorized assessments only.

## Why this tool exists

Cross-Origin Resource Sharing (CORS) is a browser mechanism that permits controlled resource access across origins. Misconfigurations often expose:

- authenticated user data
- tokens and API keys
- sensitive headers
- privileged API functionality
- cached responses across origins

A single weak CORS rule can turn a seemingly harmless web app into a data exposure vector.

## What the scanner checks

The scanner tests the following high-impact patterns:

1. Wildcard ACAO
2. Reflected origin
3. Null origin trust
4. Credentialed cross-origin access
5. Wildcard + credentials conflict
6. Subdomain wildcard trust
7. Origin validation bypass
8. Dangerous methods allowed in preflight
9. Sensitive headers exposed
10. Missing Vary: Origin / cache poisoning risk

Each finding includes:

- severity
- exploitability level
- evidence
- impact assessment
- remediation guidance
- PoC hint

## Quick start

### Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Single target

```bash
python cors_scanner.py -u https://api.example.com
```

### Verbose output

```bash
python cors_scanner.py -u https://api.example.com --verbose --red-team
```

### Bulk scan from file

```bash
python cors_scanner.py -f targets.txt --threads 20 --output report.json --red-team
```

### Quiet mode for CI/CD

```bash
python cors_scanner.py -f targets.txt --quiet --red-team
```

### Skip SSL verification for internal or staging targets

```bash
python cors_scanner.py -u https://internal.corp --no-ssl-verify --red-team
```

## CLI usage

```bash
python cors_scanner.py -h
```

### Supported flags

- `-u, --url`: scan a single URL
- `-f, --file`: scan multiple targets from a file
- `--threads`: concurrency level
- `--timeout`: per-request timeout
- `--no-ssl-verify`: disable cert verification
- `-v, --verbose`: print evidence and remediation details
- `--red-team`: enable exploitability scoring and PoC hints
- `-o, --output`: save JSON report
- `--output-txt`: save plain-text report
- `-q, --quiet`: only print vulnerable targets

## Output model

The scanner returns structured results with a finding schema like this:

```json
{
  "check_id": "CORS_002",
  "check": "Reflected Origin Allowed",
  "severity": "CRITICAL",
  "exploitability": "IMMEDIATE",
  "description": "Server blindly reflects any supplied Origin header back in ACAO.",
  "evidence": "Origin sent: https://evil-attacker.com\nAccess-Control-Allow-Origin: https://evil-attacker.com",
  "impact": "Attacker can read authenticated API responses from the victim's browser.",
  "remediation": "Validate Origin against a strict whitelist using exact string comparison.",
  "poc_hint": "fetch('https://target.com/api', {credentials: 'include'})..."
}
```

## Red-team mode

The `--red-team` mode is intended to help analysts prioritize findings by:

- exploitability level
- likely impact
- operational simplicity
- required conditions for exploitation

This makes it more useful for live engagements, bug bounty triage, and professional vulnerability assessments.

## Responsible use

This tool is meant for:

- internal security testing
- authorized penetration testing
- red-team validation
- research on systems you own or are explicitly allowed to test

Do not use it against systems without proper authorization.

## Notes

- This is a focused CORS scanner, not a full browser automation framework.
- Some findings require a valid authenticated session or browser context to demonstrate full exploitation.
- Results should be validated manually in a real browser before concluding impact.

## Reporting

The scanner can export:

- JSON reports for automation and pipelines
- plain text summaries for manual review
- structured output suitable for ticketing or assessment workflows

## License

This project is distributed without a formal license file at the moment. Respect local laws and authorization requirements before testing systems.

