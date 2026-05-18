#!/usr/bin/env python3
"""JuicyJS - JavaScript Security Analyzer for Bug Bounty Hunters"""

import re
import os
import sys
import json
import argparse
import html as html_mod
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional


# ─── ANSI Colors (no external deps) ────────────────────────────────────────
class C:
    RED    = '\033[91m'
    ORANGE = '\033[38;5;208m'
    YELLOW = '\033[93m'
    GREEN  = '\033[92m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    MAGENTA= '\033[95m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'

    @classmethod
    def disable(cls):
        for attr in ['RED','ORANGE','YELLOW','GREEN','BLUE','CYAN','MAGENTA','WHITE','BOLD','DIM','RESET']:
            setattr(cls, attr, '')


SEVERITY_ORDER  = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
SEVERITY_COLORS = {
    'CRITICAL': '\033[91m',
    'HIGH':     '\033[38;5;208m',
    'MEDIUM':   '\033[93m',
    'LOW':      '\033[96m',
    'INFO':     '\033[94m',
}
SEVERITY_HTML = {
    'CRITICAL': '#dc3545',
    'HIGH':     '#fd7e14',
    'MEDIUM':   '#ffc107',
    'LOW':      '#17a2b8',
    'INFO':     '#6c757d',
}


# ─── Detection Patterns ─────────────────────────────────────────────────────
# Each pattern:  name, severity, regex, group (capture group to highlight),
#                description (actionable bounty guidance), tags
PATTERNS: List[Dict] = [

    # ══════════════════════════ CRITICAL ══════════════════════════
    {
        "name": "AWS Access Key ID",
        "severity": "CRITICAL",
        "regex": r'(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])',
        "group": 0,
        "description": (
            "AWS Access Key ID found. Steps: (1) Check paired secret key nearby. "
            "(2) Run: aws sts get-caller-identity. "
            "(3) List IAM permissions to determine blast radius. "
            "Report impact: data exfiltration, privilege escalation, resource abuse."
        ),
        "tags": ["aws", "credentials", "cloud"],
    },
    {
        "name": "AWS Secret Access Key",
        "severity": "CRITICAL",
        "regex": r'(?i)(?:aws.{0,30}(?:secret|key)|(?:secret|key).{0,30}aws).{0,30}["\']([A-Za-z0-9/+=]{40})["\']',
        "group": 1,
        "description": (
            "AWS Secret Access Key. Combine with AKIA* key for API access. "
            "Verify with: aws configure then aws sts get-caller-identity."
        ),
        "tags": ["aws", "credentials", "cloud"],
    },
    {
        "name": "Private Key (PEM)",
        "severity": "CRITICAL",
        "regex": r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----',
        "group": 0,
        "description": (
            "Embedded private key. Extract full key block. "
            "Can be used for TLS impersonation, SSH access, JWT signing, or code signing."
        ),
        "tags": ["crypto", "pem", "rsa", "ssh"],
    },
    {
        "name": "Stripe Secret Key (Live)",
        "severity": "CRITICAL",
        "regex": r'sk_live_[0-9A-Za-z]{24,}',
        "group": 0,
        "description": (
            "Stripe live secret key. Full access to payment processing, refunds, "
            "customer PII, and subscription management. High bounty potential."
        ),
        "tags": ["stripe", "payment", "credentials"],
    },
    {
        "name": "URL with Embedded Credentials",
        "severity": "CRITICAL",
        "regex": r'https?://[A-Za-z0-9._%+\-]+:[A-Za-z0-9._%+\-@!#$&*+/=?^_`{|}~]{3,}@[^\s"\'`<>]{5,}',
        "group": 0,
        "description": (
            "URL with username:password in plaintext. "
            "Test the credentials against the service directly."
        ),
        "tags": ["credentials", "url"],
    },
    {
        "name": "Database Connection String",
        "severity": "CRITICAL",
        "regex": r'(?i)(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|mssql|sqlserver|oracle)://[A-Za-z0-9._%+\-]+:[^@\s"\'`]{3,}@[^\s"\'`<>]+',
        "group": 0,
        "description": (
            "Database connection string with credentials. "
            "Verify connectivity from external network. "
            "Check for publicly exposed DB port (3306, 5432, 27017, 6379)."
        ),
        "tags": ["database", "credentials"],
    },
    {
        "name": "GitHub Personal Access Token",
        "severity": "CRITICAL",
        "regex": r'(?<![A-Za-z0-9_-])(gh[pousr]_[A-Za-z0-9]{36,255})(?![A-Za-z0-9_-])',
        "group": 1,
        "description": (
            "GitHub PAT. Test: curl -H 'Authorization: token TOKEN' https://api.github.com/user. "
            "May access private repos, org secrets, CI/CD pipelines."
        ),
        "tags": ["github", "credentials", "vcs"],
    },
    {
        "name": "Google OAuth Client Secret",
        "severity": "CRITICAL",
        "regex": r'(?i)client.?secret["\']?\s*[:=]\s*["\']?(GOCSPX-[A-Za-z0-9_-]{28})["\']?',
        "group": 1,
        "description": (
            "Google OAuth2 client secret. Can be used to obtain OAuth tokens "
            "and impersonate application in OAuth flows."
        ),
        "tags": ["google", "oauth", "credentials"],
    },

    # ══════════════════════════ HIGH ══════════════════════════
    {
        "name": "Google API Key",
        "severity": "HIGH",
        "regex": r'(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z\-_]{35})(?![A-Za-z0-9_-])',
        "group": 1,
        "description": (
            "Google API Key. Test enabled APIs: Maps, Translate, YouTube, Cloud. "
            "Check restrictions at console.cloud.google.com. "
            "Unrestricted keys can be abused for quota theft."
        ),
        "tags": ["google", "api-key"],
    },
    {
        "name": "Firebase API Key",
        "severity": "HIGH",
        "regex": r'["\']apiKey["\']\s*:\s*["\'](AIza[0-9A-Za-z\-_]{35})["\']',
        "group": 1,
        "description": (
            "Firebase API Key in config object. "
            "Test Firestore/RTDB security rules: GET https://PROJECT.firebaseio.com/.json. "
            "Misconfigured rules can expose all user data."
        ),
        "tags": ["firebase", "google", "api-key"],
    },
    {
        "name": "Hardcoded JWT Token",
        "severity": "HIGH",
        "regex": r'(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,})(?![A-Za-z0-9_-])',
        "group": 1,
        "description": (
            "Hardcoded JWT. Decode at jwt.io — check exp, alg (esp. 'none' or HS256 with weak secret), "
            "and claims (role, admin). Test if token is still valid."
        ),
        "tags": ["jwt", "auth"],
    },
    {
        "name": "SendGrid API Key",
        "severity": "HIGH",
        "regex": r'(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})',
        "group": 1,
        "description": (
            "SendGrid API Key. Can send emails as the domain (phishing risk), "
            "access contact lists, and view email activity."
        ),
        "tags": ["sendgrid", "email", "api-key"],
    },
    {
        "name": "Slack Bot/User Token",
        "severity": "HIGH",
        "regex": r'(xox[baprs]-[0-9]{1,20}-[0-9]{1,20}-[0-9A-Za-z]{20,})',
        "group": 1,
        "description": (
            "Slack API token. Test: curl -H 'Authorization: Bearer TOKEN' "
            "https://slack.com/api/auth.test. "
            "Access messages, files, user lists depending on scopes."
        ),
        "tags": ["slack", "credentials"],
    },
    {
        "name": "Slack Incoming Webhook",
        "severity": "HIGH",
        "regex": r'(https://hooks\.slack\.com/services/T[A-Z0-9]{8,11}/B[A-Z0-9]{8,11}/[A-Za-z0-9]{24,})',
        "group": 1,
        "description": (
            "Slack Incoming Webhook URL. Can post arbitrary messages to the channel. "
            "Test: curl -X POST -d '{\"text\":\"test\"}' WEBHOOK_URL"
        ),
        "tags": ["slack", "webhook"],
    },
    {
        "name": "Twilio Auth Token",
        "severity": "HIGH",
        "regex": r'(?i)twilio[^"\'`\n]{0,60}["\']([a-f0-9]{32})["\']',
        "group": 1,
        "description": (
            "Twilio Auth Token. Combined with Account SID: full account access, "
            "make calls, send SMS, access call logs/recordings."
        ),
        "tags": ["twilio", "credentials"],
    },
    {
        "name": "Hardcoded Password",
        "severity": "HIGH",
        "regex": r'(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*["\']([^"\']{4,64})["\']',
        "group": 1,
        "description": (
            "Hardcoded password. Try against login forms, APIs, admin panels, "
            "and check for password reuse across services."
        ),
        "tags": ["credentials", "password"],
    },
    {
        "name": "Hardcoded Secret / API Key",
        "severity": "HIGH",
        "regex": r'(?i)(?:secret_key|secret_token|auth_token|api_key|api_secret|app_secret|access_token|client_secret|app_key|service_key)\s*[:=]\s*["\']([^"\']{8,})["\']',
        "group": 1,
        "description": "Hardcoded secret or API key in variable. Identify the service from context and test.",
        "tags": ["credentials", "secret"],
    },
    {
        "name": "OAuth 2.0 Client Secret",
        "severity": "HIGH",
        "regex": r'(?i)client.?secret\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{10,})["\']',
        "group": 1,
        "description": (
            "OAuth 2.0 Client Secret. Use client_credentials grant to obtain access tokens: "
            "POST /oauth/token with client_id + client_secret."
        ),
        "tags": ["oauth", "credentials"],
    },
    {
        "name": "Heroku API Key",
        "severity": "HIGH",
        "regex": r'(?i)heroku[^"\'`\n]{0,30}["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
        "group": 1,
        "description": "Heroku API Key. Access app configs (env vars!), deploy code, manage addons.",
        "tags": ["heroku", "credentials", "cloud"],
    },
    {
        "name": "Stripe Live Publishable Key",
        "severity": "HIGH",
        "regex": r'(pk_live_[0-9A-Za-z]{24,})',
        "group": 1,
        "description": (
            "Stripe live publishable key. Verify no secret key nearby. "
            "Note for report: confirms live payment integration."
        ),
        "tags": ["stripe", "payment"],
    },
    {
        "name": "Mailgun API Key",
        "severity": "HIGH",
        "regex": r'(?i)(key-[0-9a-zA-Z]{32})',
        "group": 1,
        "description": "Mailgun API Key. Can send emails, access logs, manage domains.",
        "tags": ["mailgun", "email", "api-key"],
    },
    {
        "name": "Mailchimp API Key",
        "severity": "HIGH",
        "regex": r'([0-9a-f]{32}-us[0-9]{1,2})',
        "group": 1,
        "description": "Mailchimp API Key. Access mailing lists, subscriber PII, campaigns.",
        "tags": ["mailchimp", "email", "api-key"],
    },
    {
        "name": "NPM Auth Token",
        "severity": "HIGH",
        "regex": r'(?i)(?://registry\.npmjs\.org/:_authToken\s*=\s*|npm_token\s*[:=]\s*["\']?)([A-Za-z0-9_-]{36,})',
        "group": 1,
        "description": "NPM auth token. Can publish packages to npm — supply chain risk.",
        "tags": ["npm", "credentials", "supply-chain"],
    },
    {
        "name": "Shopify Access Token",
        "severity": "HIGH",
        "regex": r'shpat_[A-Za-z0-9]{32}',
        "group": 0,
        "description": "Shopify Admin API access token. Full store access including orders, customers.",
        "tags": ["shopify", "credentials", "ecommerce"],
    },
    {
        "name": "Twilio Account SID",
        "severity": "HIGH",
        "regex": r'(?<![A-Z0-9])(AC[a-f0-9]{32})(?![a-f0-9])',
        "group": 1,
        "description": "Twilio Account SID. Pair with Auth Token (32-char hex) for full API access.",
        "tags": ["twilio"],
    },

    # ══════════════════════════ MEDIUM ══════════════════════════
    {
        "name": "Admin / Internal Endpoint",
        "severity": "MEDIUM",
        "regex": r"""(?:["'`])(/(?:admin|internal|debug|test|dev|staging|management|console|dashboard|backstage|superuser|staff|operator|api/internal|_internal|__debug)[^\s"'`<>\[\]{}\\]{0,120})["'`]""",
        "group": 1,
        "description": (
            "Admin/internal/debug endpoint. Test for: broken access control (access as low-priv user), "
            "IDOR, unauthenticated access, info disclosure."
        ),
        "tags": ["endpoint", "admin", "idor"],
    },
    {
        "name": "AWS S3 Bucket",
        "severity": "MEDIUM",
        "regex": r'(?i)(?:s3://([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])|https?://([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])\.s3[.\-][a-z0-9\-]*\.amazonaws\.com|s3\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]))',
        "group": 0,
        "description": (
            "S3 bucket reference. Test: aws s3 ls s3://BUCKET --no-sign-request. "
            "Check for public read/write, directory listing."
        ),
        "tags": ["aws", "s3", "storage"],
    },
    {
        "name": "Firebase Realtime Database URL",
        "severity": "MEDIUM",
        "regex": r'(https://[a-z0-9\-]+\.firebaseio\.com)',
        "group": 1,
        "description": (
            "Firebase RTDB URL. Test unauthenticated access: "
            "curl 'https://PROJECT.firebaseio.com/.json'. "
            "Also try /.json?shallow=true for large databases."
        ),
        "tags": ["firebase", "database", "nosql"],
    },
    {
        "name": "Internal IP Address",
        "severity": "MEDIUM",
        "regex": r'(?<![0-9.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.\d{1,3}|0\.0\.0\.0)(?![0-9.])',
        "group": 0,
        "description": "RFC 1918 / loopback IP. May reveal internal network topology or SSRF targets.",
        "tags": ["network", "ip", "ssrf"],
    },
    {
        "name": "Mapbox Access Token",
        "severity": "MEDIUM",
        "regex": r'(pk\.eyJ1[A-Za-z0-9._-]{50,})',
        "group": 1,
        "description": "Mapbox public token. Check if scoped beyond map rendering; test for token abuse.",
        "tags": ["mapbox", "api-key"],
    },
    {
        "name": "Stripe Test Key",
        "severity": "MEDIUM",
        "regex": r'(?:sk|pk)_test_[0-9A-Za-z]{24,}',
        "group": 0,
        "description": "Stripe test mode key. Note for report; verify no live key nearby.",
        "tags": ["stripe", "payment", "test"],
    },
    {
        "name": "GraphQL Endpoint",
        "severity": "MEDIUM",
        "regex": r"""(?i)["'`]([^\s"'`]*graphql[^\s"'`]*)["'`]""",
        "group": 1,
        "description": (
            "GraphQL endpoint. Test: POST with {\"query\":\"{__schema{types{name}}}\"} for introspection. "
            "Look for mutations that bypass REST-level auth."
        ),
        "tags": ["graphql", "endpoint"],
    },
    {
        "name": "Source Map Reference",
        "severity": "MEDIUM",
        "regex": r'//[#@]\s*sourceMappingURL=([^\s]+\.map)',
        "group": 1,
        "description": (
            "Source map file referenced. Download it to access original unminified source code. "
            "Tool: curl URL.map | python3 -c \"import json,sys; [print(f) for f in json.load(sys.stdin).get('sources',[])]"
        ),
        "tags": ["source-map", "recon"],
    },
    {
        "name": "Exposed .env / Config Variable Names",
        "severity": "MEDIUM",
        "regex": r'process\.env\.([A-Z][A-Z0-9_]{2,50})',
        "group": 1,
        "description": (
            "Node.js env variable reference. Build a list of expected variable names. "
            "Check if .env file is exposed (/.env, /.env.local, /.env.production)."
        ),
        "tags": ["env", "node", "recon"],
    },
    {
        "name": "WebSocket Endpoint",
        "severity": "MEDIUM",
        "regex": r'(wss?://[^\s"\'`<>]{5,120})',
        "group": 1,
        "description": (
            "WebSocket endpoint. Test for: missing origin validation (CSWSH), "
            "lack of auth on connect, message injection."
        ),
        "tags": ["websocket", "endpoint"],
    },
    {
        "name": "IDOR-Prone API Pattern",
        "severity": "MEDIUM",
        "regex": r"""(?i)["'`](/(?:api|v[0-9]+)/[^\s"'`<>]*(?:user|account|profile|order|invoice|document|file|report|ticket)[^\s"'`<>]*(?:/\{?(?:id|user_id|uid|account_id)[^"'`]*\}?|/:[a-z_]+id))["'`]""",
        "group": 1,
        "description": (
            "API endpoint pattern with object ID parameter. "
            "Test for IDOR: access another user's resource by changing the ID."
        ),
        "tags": ["idor", "endpoint", "api"],
    },

    # ══════════════════════════ LOW ══════════════════════════
    {
        "name": "Sensitive Code Comment",
        "severity": "LOW",
        "regex": r'//[^\n]*\b(?:todo|fixme|hack|password|secret|key|token|api|bug|vuln|vulnerable|backdoor|bypass|hardcoded|remove|disable|skip)\b[^\n]*',
        "group": 0,
        "description": "Developer comment referencing sensitive topic. May hint at known vulnerabilities.",
        "tags": ["comment", "developer-notes"],
    },
    {
        "name": "Debug / Verbose Mode Flag",
        "severity": "LOW",
        "regex": r'(?i)(?:debug|verbose|devMode|isDev|development)\s*[:=]\s*(?:true|1)',
        "group": 0,
        "description": "Debug or development mode enabled. May expose extra error info, stack traces.",
        "tags": ["debug", "misconfiguration"],
    },
    {
        "name": "console.log with Sensitive Data",
        "severity": "LOW",
        "regex": r'console\.(?:log|warn|error|debug)\([^\n]*(?:password|token|secret|key|auth|credential)[^\n]*\)',
        "group": 0,
        "description": "console.log statement logging potentially sensitive data.",
        "tags": ["debug", "logging"],
    },

    # ══════════════════════════ INFO ══════════════════════════
    {
        "name": "API Endpoint",
        "severity": "INFO",
        "regex": r"""(?:["'`])(/(?:api|v[0-9]+)/[^\s"'`<>\[\]{}\\]{2,100})["'`]""",
        "group": 1,
        "description": "API endpoint path. Build a complete endpoint map for further testing.",
        "tags": ["endpoint", "api"],
    },
    {
        "name": "Email Address",
        "severity": "INFO",
        "regex": r'\b([A-Za-z0-9._%+\-]+@(?!example\.com|test\.com|domain\.com|email\.com)[A-Za-z0-9.\-]+\.[A-Za-z]{2,7})\b',
        "group": 1,
        "description": "Email address. Internal emails may indicate staff accounts to target.",
        "tags": ["email", "pii", "recon"],
    },
    {
        "name": "Version Disclosure",
        "severity": "INFO",
        "regex": r'(?i)["\']?(?:version|ver)["\']?\s*[:=]\s*["\']([0-9]+\.[0-9]+[^\s"\']{0,20})["\']',
        "group": 1,
        "description": "Version string. Cross-reference with NVD/CVE databases for known vulnerabilities.",
        "tags": ["version", "recon"],
    },
    {
        "name": "Hardcoded Domain / Staging URL",
        "severity": "INFO",
        "regex": r'(?i)https?://(?:api|staging|dev|internal|test|admin|backend|management|preprod)\.[a-z0-9\-]+\.[a-z]{2,}[^\s"\'`<>]{0,100}',
        "group": 0,
        "description": "Non-production or internal subdomain. Test for weaker auth, older software versions.",
        "tags": ["url", "recon", "staging"],
    },
    {
        "name": "CORS Configuration",
        "severity": "INFO",
        "regex": r'(?i)(?:Access-Control-Allow-Origin|allowedOrigins|corsOrigin)\s*[:=]\s*["\']?(\*|https?://[^\s"\']+)',
        "group": 1,
        "description": "CORS origin configuration. '*' = any origin; test for CORS + credentials combo.",
        "tags": ["cors", "misconfiguration"],
    },
]


# ─── Core scanning logic ────────────────────────────────────────────────────

def get_line_and_context(content: str, match_start: int, context_lines: int) -> Tuple[int, List[str], int]:
    lines = content.split('\n')
    pos = 0
    line_num = len(lines)
    for i, line in enumerate(lines):
        if pos + len(line) + 1 > match_start:
            line_num = i + 1
            break
        pos += len(line) + 1
    start = max(0, line_num - 1 - context_lines)
    end   = min(len(lines), line_num + context_lines)
    return line_num, lines[start:end], start + 1


def trunc(s: str, n: int = 150) -> str:
    return s[:n] + '…' if len(s) > n else s


def is_minified(content: str) -> bool:
    lines = content.split('\n')
    if not lines:
        return False
    avg_len = sum(len(l) for l in lines) / len(lines)
    return avg_len > 500 or (len(lines) < 10 and len(content) > 5000)


def scan_content(content: str, filename: str, context_lines: int = 2) -> List[Dict]:
    findings: List[Dict] = []
    seen: set = set()

    for pat in PATTERNS:
        flags = 0
        regex_str = pat['regex']
        try:
            rx = re.compile(regex_str, flags)
        except re.error as e:
            continue

        for m in rx.finditer(content):
            grp = pat.get('group', 0)
            try:
                value = m.group(grp) or m.group(0)
            except IndexError:
                value = m.group(0)
            value = (value or '').strip()
            if not value:
                continue

            dedup = (pat['name'], value[:60])
            if dedup in seen:
                continue
            seen.add(dedup)

            line_num, ctx, ctx_start = get_line_and_context(content, m.start(), context_lines)

            findings.append({
                'file':        filename,
                'pattern':     pat['name'],
                'severity':    pat['severity'],
                'description': pat['description'],
                'tags':        pat.get('tags', []),
                'value':       value,
                'full_match':  trunc(m.group(0)),
                'line':        line_num,
                'context':     ctx,
                'ctx_start':   ctx_start,
            })

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x['severity'], 99))
    return findings


# ─── Terminal output ─────────────────────────────────────────────────────────

AUTHOR = "Vivek Goswami"
LINKEDIN = "https://www.linkedin.com/in/vivekgoswmii"


def print_banner():
    print(f"""
{C.BOLD}{C.YELLOW} ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
 ░  ██╗██╗   ██╗██╗ ██████╗██╗   ██╗     ██╗███████╗          ░
 ░  ██║██║   ██║██║██╔════╝╚██╗ ██╔╝     ██║██╔════╝          ░
 ░  ██║██║   ██║██║██║      ╚████╔╝      ██║███████╗          ░
 ░  ██║██║   ██║██║██║       ╚██╔╝  ██   ██║╚════██║          ░
 ░  ██║╚██████╔╝██║╚██████╗   ██║   ╚█████╔╝███████║          ░
 ░  ╚═╝ ╚═════╝ ╚═╝ ╚═════╝   ╚═╝    ╚════╝ ╚══════╝          ░
 ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░{C.RESET}
{C.DIM}   Extract juicy secrets & endpoints from JS files for bug bounty{C.RESET}
{C.DIM}   Author: {AUTHOR}  |  {LINKEDIN}{C.RESET}
""")


def sev_color(sev: str) -> str:
    return SEVERITY_COLORS.get(sev, C.WHITE)


def print_finding(f: Dict, verbose: bool = False):
    sc = sev_color(f['severity'])
    print(f"\n  {C.BOLD}{sc}[{f['severity']}]{C.RESET}  {C.BOLD}{f['pattern']}{C.RESET}")
    print(f"  {C.DIM}File  :{C.RESET} {f['file']}:{C.CYAN}{f['line']}{C.RESET}")
    print(f"  {C.DIM}Value :{C.RESET} {C.GREEN}{trunc(f['value'], 120)}{C.RESET}")
    # Always show impact for HIGH/CRITICAL; show for others only with --verbose
    if verbose or f['severity'] in ('CRITICAL', 'HIGH'):
        print(f"  {C.DIM}Impact:{C.RESET} {f['description']}")
    if f['tags']:
        tags = '  '.join(f['tags'])
        print(f"  {C.DIM}Tags  :{C.RESET} {C.DIM}{tags}{C.RESET}")
    if f['context']:
        print(f"  {C.DIM}─────── context ───────{C.RESET}")
        for i, line in enumerate(f['context']):
            ln = f['ctx_start'] + i
            is_hit = (ln == f['line'])
            marker = f"  {C.BOLD}{sc}▶{C.RESET}" if is_hit else "   "
            print(f"{marker} {C.DIM}{ln:4d}{C.RESET}  {trunc(line.rstrip(), 130)}")


def print_summary(findings: List[Dict], files_count: int, elapsed: float = 0):
    counts = defaultdict(int)
    for f in findings:
        counts[f['severity']] += 1

    print(f"\n{C.BOLD}{'═'*65}{C.RESET}")
    print(f"{C.BOLD}  SCAN COMPLETE{C.RESET}")
    print(f"{'═'*65}")
    print(f"  Files scanned  : {C.BOLD}{files_count}{C.RESET}")
    print(f"  Total findings : {C.BOLD}{len(findings)}{C.RESET}")
    if elapsed:
        print(f"  Time           : {elapsed:.2f}s")
    print()
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        n = counts[sev]
        if n:
            sc = sev_color(sev)
            bar = '█' * min(n, 40)
            print(f"  {sc}{C.BOLD}{sev:10}{C.RESET}  {sc}{bar}{C.RESET}  {n}")
    print(f"{'═'*65}\n")


# ─── HTML Report ─────────────────────────────────────────────────────────────

def generate_html_report(findings: List[Dict], files_count: int, output_path: str):
    counts = defaultdict(int)
    for f in findings:
        counts[f['severity']] += 1

    stats_html = ''.join(
        f'<div class="stat"><div class="num" style="color:{SEVERITY_HTML[s]}">{counts[s]}</div>'
        f'<div class="label">{s}</div></div>'
        for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']
    )

    rows = ''
    for f in findings:
        color = SEVERITY_HTML.get(f['severity'], '#666')
        ctx_rows = ''
        for i, ln_text in enumerate(f['context']):
            ln = f['ctx_start'] + i
            hl = 'background:#2d2a00;' if ln == f['line'] else ''
            ctx_rows += (
                f'<tr style="{hl}"><td class="ln">{ln}</td>'
                f'<td><code>{html_mod.escape(ln_text.rstrip())}</code></td></tr>'
            )
        tags_html = ''.join(f'<span class="tag">{t}</span>' for t in f['tags'])
        rows += f'''
        <div class="card">
          <div class="card-head" style="border-left:4px solid {color}">
            <span class="badge" style="background:{color}">{f["severity"]}</span>
            <span class="pname">{html_mod.escape(f["pattern"])}</span>
            <span class="loc">{html_mod.escape(f["file"])}:{f["line"]}</span>
          </div>
          <div class="card-body">
            <div class="val"><b>Value:</b> <code>{html_mod.escape(trunc(f["value"], 300))}</code></div>
            <div class="desc">{html_mod.escape(f["description"])}</div>
            <div class="tags">{tags_html}</div>
            <table class="ctx">{ctx_rows}</table>
          </div>
        </div>'''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JuicyJS Report – {datetime.now():%Y-%m-%d %H:%M}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,monospace;background:#0d1117;color:#c9d1d9;padding:24px;line-height:1.6}}
h1{{color:#58a6ff;margin-bottom:4px;font-size:1.6em}}
.meta{{color:#8b949e;font-size:.85em;margin-bottom:20px}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 22px;text-align:center;min-width:90px}}
.num{{font-size:1.9em;font-weight:700}}
.label{{font-size:.72em;color:#8b949e;margin-top:2px;letter-spacing:.05em}}
.filters{{margin:16px 0;display:flex;gap:8px;flex-wrap:wrap}}
.filters button{{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:5px 14px;border-radius:20px;cursor:pointer;font-size:.82em;transition:.15s}}
.filters button:hover,.filters button.active{{background:#1f6feb;border-color:#1f6feb;color:#fff}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;margin:14px 0;overflow:hidden;transition:.2s}}
.card:hover{{border-color:#388bfd44}}
.card-head{{padding:11px 16px;display:flex;align-items:center;gap:10px;background:#1c2128}}
.badge{{padding:2px 9px;border-radius:4px;font-size:.72em;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:.06em}}
.pname{{font-weight:600;font-size:1em}}
.loc{{color:#8b949e;font-size:.8em;margin-left:auto;font-family:monospace}}
.card-body{{padding:14px 16px}}
.val{{margin:6px 0 4px;word-break:break-all}}
.val code{{background:#0d1117;padding:3px 8px;border-radius:4px;color:#79c0ff;font-size:.85em}}
.desc{{color:#8b949e;font-size:.88em;margin:8px 0 6px}}
.tags{{margin:6px 0 8px}}
.tag{{background:#21262d;color:#58a6ff;padding:2px 9px;border-radius:12px;font-size:.72em;margin-right:5px;display:inline-block}}
.ctx{{width:100%;border-collapse:collapse;margin-top:8px;font-size:.82em;background:#0d1117;border-radius:6px;overflow:hidden}}
.ctx td{{padding:2px 10px;font-family:monospace}}
.ln{{color:#484f58;user-select:none;text-align:right;width:46px;border-right:1px solid #21262d}}
.hidden{{display:none}}
</style>
</head>
<body>
<h1>JuicyJS — JS Security Analysis Report</h1>
<div class="meta">
  Generated {datetime.now():%Y-%m-%d %H:%M:%S} &nbsp;|&nbsp;
  Files scanned: {files_count} &nbsp;|&nbsp;
  Findings: {len(findings)}
</div>
<div class="stats">{stats_html}</div>
<div class="filters" id="filters">
  <button class="active" onclick="filter('ALL',this)">All</button>
  <button onclick="filter('CRITICAL',this)" style="color:#dc3545">CRITICAL</button>
  <button onclick="filter('HIGH',this)" style="color:#fd7e14">HIGH</button>
  <button onclick="filter('MEDIUM',this)" style="color:#ffc107">MEDIUM</button>
  <button onclick="filter('LOW',this)" style="color:#17a2b8">LOW</button>
  <button onclick="filter('INFO',this)" style="color:#6c757d">INFO</button>
</div>
<div id="cards">{rows}</div>
<div style="margin-top:40px;padding-top:20px;border-top:1px solid #21262d;color:#484f58;font-size:.8em;text-align:center">
  JuicyJS &nbsp;|&nbsp; Author: <a href="{LINKEDIN}" target="_blank" style="color:#58a6ff;text-decoration:none">{AUTHOR}</a>
  &nbsp;|&nbsp; {LINKEDIN}
</div>
<script>
function filter(sev, btn) {{
  document.querySelectorAll('.filters button').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.card').forEach(c => {{
    const b = c.querySelector('.badge');
    c.classList.toggle('hidden', sev !== 'ALL' && b && b.textContent !== sev);
  }});
}}
</script>
</body>
</html>'''

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    print(f"{C.GREEN}[+] HTML report saved → {output_path}{C.RESET}")


# ─── File collection & .txt / URL handling ───────────────────────────────────

JS_EXTENSIONS  = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte'}
ALL_EXTENSIONS = JS_EXTENSIONS | {'.txt'}

# Regex to recognise a line that is a bare URL
_URL_RE = re.compile(r'^https?://\S+', re.IGNORECASE)


def _is_url_list(text: str) -> bool:
    """Return True when the majority of non-empty lines look like URLs."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return False
    url_count = sum(1 for l in lines if _URL_RE.match(l))
    return url_count / len(lines) >= 0.5


def fetch_url(url: str, timeout: int = 15) -> Optional[str]:
    """Fetch a URL and return its body as text, or None on any error."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': (
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/124.0.0.0 Safari/537.36'
                )
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return resp.read().decode('utf-8', errors='replace')
    except Exception:
        pass
    return None


def process_txt_file(path: Path) -> List[Tuple[str, str]]:
    """
    Process a .txt file and return a list of (js_content, source_label) pairs.

    Two modes:
      • URL list  — each line is a JS URL  → fetch every URL, return responses
      • JS dump   — the file itself is JS  → return the file content directly
    """
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        print(f"{C.YELLOW}[!] Cannot read {path}: {e}{C.RESET}")
        return []

    if _is_url_list(text):
        urls = [l.strip() for l in text.splitlines()
                if l.strip() and _URL_RE.match(l.strip())]
        print(f"\n{C.BOLD}{C.MAGENTA}[TXT]{C.RESET} {path}  "
              f"{C.DIM}→ URL list detected ({len(urls)} URL{'' if len(urls)==1 else 's'}){C.RESET}")
        sources: List[Tuple[str, str]] = []
        for url in urls:
            label = trunc(url, 80)
            print(f"  {C.DIM}fetching{C.RESET} {label} … ", end='', flush=True)
            content = fetch_url(url)
            if content:
                print(f"{C.GREEN}✓ {len(content):,} bytes{C.RESET}")
                sources.append((content, url))
            else:
                print(f"{C.RED}✗ failed / unreachable{C.RESET}")
        return sources
    else:
        print(f"\n{C.BOLD}{C.MAGENTA}[TXT]{C.RESET} {path}  "
              f"{C.DIM}→ JS content file{C.RESET}")
        return [(text, str(path))]


def collect_files(targets: List[str]) -> List[Path]:
    files: List[Path] = []
    for t in targets:
        p = Path(t)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for ext in ALL_EXTENSIONS:
                files.extend(p.rglob(f'*{ext}'))
        else:
            import glob as _glob
            matched = _glob.glob(t)
            if matched:
                files.extend(Path(m) for m in matched if Path(m).is_file())
            else:
                print(f"{C.YELLOW}[!] Not found: {t}{C.RESET}")
    return sorted(set(files))


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    import time

    parser = argparse.ArgumentParser(
        prog='juicyjs',
        description='JuicyJS – Analyze JS files in a folder and extract sensitive info for bug bounty',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
USAGE
  Give it a folder, a JS file, or a .txt file.
  Folders are scanned recursively for .js .jsx .ts .tsx .mjs .cjs .vue .svelte
  and also .txt files (auto-detected as JS content or URL lists).

  .txt AUTO-DETECTION:
    • If majority of lines are URLs  → fetches each URL and scans the response
    • Otherwise                      → treats the file as saved JS content

EXAMPLES
  juicyjs.py /path/to/js-folder/
  juicyjs.py urls.txt                            (URL list — fetches each one)
  juicyjs.py saved_script.txt                    (JS saved as .txt)
  juicyjs.py ./js/ urls.txt                      (mix folder + txt file)
  juicyjs.py ./js/ --min-severity HIGH
  juicyjs.py ./js/ --output report.html          (HTML with filter buttons)
  juicyjs.py ./js/ --json findings.json          (machine-readable)
  juicyjs.py ./js/ --verbose                     (show full impact description)
  juicyjs.py ./js/ --tags aws credentials        (filter by tag)
  juicyjs.py ./js/ --context 5                   (more surrounding code)
  juicyjs.py --list-patterns                     (show all 40+ detection rules)

TIPS
  • Tools like gau/waybackurls output URL lists — save to .txt and feed directly
  • Run js-beautify on minified files first for better context lines
  • --min-severity HIGH cuts noise; use INFO for full recon
  • HTML report has filter buttons — perfect for sharing with program triagers
  • If you see a source map (.map) reference, download it for original source
        '''
    )
    parser.add_argument('targets', nargs='*',
                        help='Folder(s), JS file(s), or .txt files (JS content or URL lists)')
    parser.add_argument('--min-severity', '-s',
                        choices=['CRITICAL','HIGH','MEDIUM','LOW','INFO'],
                        default='INFO',
                        help='Minimum severity to display (default: INFO)')
    parser.add_argument('--context', '-c', type=int, default=2, metavar='N',
                        help='Lines of context around each match (default: 2)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show actionable description for each finding')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable ANSI color output')
    parser.add_argument('--no-banner', action='store_true',
                        help='Skip the ASCII banner')
    parser.add_argument('--json', metavar='FILE',
                        help='Export findings to JSON file')
    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Output file (.html or .json auto-detected)')
    parser.add_argument('--tags', nargs='+', metavar='TAG',
                        help='Show only findings with these tags (e.g. --tags aws credentials)')
    parser.add_argument('--list-patterns', action='store_true',
                        help='List all detection patterns and exit')

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    if not args.no_banner:
        print_banner()

    if args.list_patterns:
        print(f"{C.BOLD}{'PATTERN':<40} {'SEVERITY':<10} TAGS{C.RESET}")
        print('─' * 80)
        for p in sorted(PATTERNS, key=lambda x: SEVERITY_ORDER[x['severity']]):
            sc = sev_color(p['severity'])
            tags = ', '.join(p.get('tags', []))
            print(f"{p['name']:<40} {sc}{p['severity']:<10}{C.RESET} {tags}")
        print(f"\nTotal patterns: {len(PATTERNS)}")
        return

    if not args.targets:
        parser.print_help()
        return

    files = collect_files(args.targets)
    if not files:
        print(f"{C.RED}[-] No files found in the given targets.{C.RESET}")
        sys.exit(1)

    min_order  = SEVERITY_ORDER[args.min_severity]
    tag_filter = set(args.tags) if args.tags else None

    # ── Build list of (content, source_label) from all inputs ────────────────
    # .txt files are expanded (URL list → fetched content, or treated as JS).
    # Everything else is read directly.
    sources: List[Tuple[str, str]] = []
    txt_files  = [f for f in files if f.suffix.lower() == '.txt']
    js_files   = [f for f in files if f.suffix.lower() != '.txt']

    for fp in js_files:
        try:
            sources.append((fp.read_text(encoding='utf-8', errors='replace'), str(fp)))
        except Exception as e:
            print(f"{C.YELLOW}[!] Cannot read {fp}: {e}{C.RESET}")

    for fp in txt_files:
        sources.extend(process_txt_file(fp))

    if not sources:
        print(f"{C.RED}[-] No content to scan (all reads/fetches failed).{C.RESET}")
        sys.exit(1)

    total_sources = len(sources)
    print(f"\n{C.BOLD}Scanning {total_sources} source(s)  "
          f"|  min-severity: {args.min_severity}  "
          f"|  context: ±{args.context} lines{C.RESET}\n")

    all_findings: List[Dict] = []
    t0 = time.time()

    for content, source_name in sources:
        if is_minified(content):
            print(f"{C.YELLOW}[~] {trunc(source_name, 70)} appears minified "
                  f"— consider beautifying with js-beautify first{C.RESET}")

        raw = scan_content(content, source_name, args.context)

        filtered = [
            f for f in raw
            if SEVERITY_ORDER[f['severity']] <= min_order
            and (tag_filter is None or bool(tag_filter & set(f['tags'])))
        ]

        if filtered:
            short = trunc(source_name, 70)
            print(f"\n{C.BOLD}{C.CYAN}┌─ {short}{C.RESET}  "
                  f"{C.DIM}({len(filtered)} finding{'s' if len(filtered)!=1 else ''}){C.RESET}")
            for f in filtered:
                print_finding(f, verbose=args.verbose)
            print(f"{C.CYAN}└{'─'*60}{C.RESET}")

        all_findings.extend(filtered)

    elapsed = time.time() - t0
    print_summary(all_findings, total_sources, elapsed)

    # ── JSON export
    if args.json:
        export = [{k: v for k, v in f.items() if k not in ('context',)} for f in all_findings]
        Path(args.json).write_text(json.dumps(export, indent=2), encoding='utf-8')
        print(f"{C.GREEN}[+] JSON exported → {args.json}{C.RESET}")

    # ── --output export (auto-detect format)
    if args.output:
        out = args.output
        if out.endswith('.html') or out.endswith('.htm'):
            generate_html_report(all_findings, len(files), out)
        elif out.endswith('.json'):
            export = [{k: v for k, v in f.items() if k not in ('context',)} for f in all_findings]
            Path(out).write_text(json.dumps(export, indent=2), encoding='utf-8')
            print(f"{C.GREEN}[+] JSON exported → {out}{C.RESET}")
        else:
            # Plain text summary
            lines = []
            for f in all_findings:
                lines.append(f"[{f['severity']}] {f['pattern']}")
                lines.append(f"  File : {f['file']}:{f['line']}")
                lines.append(f"  Value: {trunc(f['value'], 150)}")
                lines.append(f"  Info : {f['description']}")
                lines.append('')
            Path(out).write_text('\n'.join(lines), encoding='utf-8')
            print(f"{C.GREEN}[+] Text report saved → {out}{C.RESET}")

    if not all_findings:
        print(f"{C.DIM}No findings matched the current filters.{C.RESET}")
    else:
        critical_high = sum(1 for f in all_findings if f['severity'] in ('CRITICAL','HIGH'))
        if critical_high:
            print(f"{C.BOLD}{C.RED}⚠  {critical_high} CRITICAL/HIGH finding(s) — review immediately!{C.RESET}\n")


if __name__ == '__main__':
    main()
