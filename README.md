# CORS Misconfiguration Scanner

Professional CORS assessment scanner for authorized security testing and red-team engagements.

This tool is designed to identify misconfigured CORS policies in web applications and APIs by testing common abuse patterns, dynamic origin validation weaknesses, credential exposure, and preflight abuse.

It is intended for legitimate security research, internal validation, and authorized assessments only.

## Why this tool exists

Cross-Origin Resource Sharing (CORS) is a browser mechanism that permits controlled resource access across origins. Weak or misapplied policies can expose:

- authenticated user data
- tokens and API keys
- sensitive headers
- privileged API actions
- cached cross-origin responses

A single weak CORS rule can turn an otherwise harmless endpoint into an active data exposure vector.

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

Every finding includes:

- severity
- exploitability level
- confidence score
- route classification
- auth requirement metadata
- chain risk
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

### Red-team assessment output

```bash
python cors_scanner.py -u https://api.example.com --verbose --red-team
```

### Bulk scan with auth context

```bash
python cors_scanner.py -f targets.txt --threads 20 --output report.json --red-team \
  --cookie "session=abc123" --header "Authorization: Bearer TOKEN" \
  --header "X-Trace-Id: redteam-123"
```

### CI/CD or quiet mode

```bash
python cors_scanner.py -f targets.txt --quiet --red-team
```

### Skip SSL verification

```bash
python cors_scanner.py -u https://internal.corp --no-ssl-verify --red-team
```

## CLI usage

```bash
python cors_scanner.py -h
```

### Supported flags

- `-u, --url`: single URL target
- `-f, --file`: list of targets, one per line
- `--threads`: concurrency
- `--timeout`: request timeout
- `--no-ssl-verify`: disable cert verification
- `-v, --verbose`: show detailed evidence and remediation
- `--red-team`: enable exploitability scoring and PoC hints
- `-o, --output`: save JSON report
- `--output-txt`: save plain-text report
- `-q, --quiet`: only print vulnerable targets
- `--header`: add custom header(s) in `Name: Value` format
- `--cookie`: add cookie(s) in `name=value` format
- `--bearer-token`: set Authorization header to `Bearer <token>`

## Output model

The scanner returns structured results including:

- severity
- exploitability
- confidence
- route context
- auth requirement status
- chain risk
- evidence
- impact
- remediation
- PoC hint

Example:

```json
{
  "check_id": "CORS_002",
  "check": "Reflected Origin Allowed",
  "severity": "CRITICAL",
  "exploitability": "IMMEDIATE",
  "confidence": "HIGH",
  "route_context": "auth",
  "requires_auth": true,
  "chain_risk": "high",
  "description": "Server reflects the supplied Origin header back in ACAO.",
  "evidence": "Origin sent: https://evil-attacker.com\nAccess-Control-Allow-Origin: https://evil-attacker.com",
  "impact": "The browser can send authenticated requests to the attacker-controlled origin.",
  "remediation": "Validate Origin against a strict whitelist.