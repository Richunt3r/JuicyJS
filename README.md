# 🍋 JuicyJS — JavaScript Security Analyzer for Bug Bounty Hunters

> Extract secrets, API keys, endpoints, credentials, and other sensitive information from JavaScript files to supercharge your bug bounty recon.

<p align="center">
  <img src="https://img.shields.io/badge/python-3.6%2B-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
  <img src="https://img.shields.io/badge/bug%20bounty-ready-red?style=flat-square" />
  <img src="https://img.shields.io/badge/patterns-44%2B-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/zero%20dependencies-✓-brightgreen?style=flat-square" />
</p>

---

## What is JuicyJS?

When doing bug bounty recon, JS files are goldmines. Developers often leave behind:
- Hardcoded API keys and secrets
- AWS/cloud credentials
- Database connection strings
- Internal admin/debug endpoints
- JWT tokens and OAuth secrets
- Internal IP addresses
- Source map references (original source code!)

JuicyJS reads every JS file in a folder you point it at, runs 44+ detection patterns against them, and gives you color-coded findings with exact line numbers, surrounding code context, and an actionable impact description for each finding.

No setup. No dependencies. Just Python 3.

---

## Features

- **44+ detection patterns** covering CRITICAL → INFO severity
- **Folder-based scanning** — point it at any directory, it recurses automatically
- **`.txt` file support** — reads JS saved as `.txt` OR auto-detects a URL list and fetches each one
- **URL list fetching** — paste a list of JS URLs in a `.txt` file; JuicyJS fetches and scans every one
- **Color-coded terminal output** with surrounding code context
- **HTML report** with severity filter buttons (great for sharing with triagers)
- **JSON export** for automated pipelines
- **Actionable impact descriptions** — every finding tells you exactly how to verify and report it
- **Minified JS detection** — warns you and suggests beautifying first
- **Zero external dependencies** — pure Python 3 standard library
- **Tag-based filtering** — `--tags aws credentials` to focus on specific categories

---

## What It Detects

| Severity   | Pattern Examples |
|------------|-----------------|
| 🔴 CRITICAL | AWS Access/Secret Keys, Private PEM Keys, Stripe Live Secret Keys, Database Connection Strings (with creds), GitHub PATs, URLs with embedded credentials |
| 🟠 HIGH     | Google API Keys, Firebase API Keys, Hardcoded JWTs, SendGrid / Slack / Twilio Tokens, Hardcoded Passwords, OAuth Client Secrets, Heroku API Keys, Shopify Tokens |
| 🟡 MEDIUM   | Admin/Internal/Debug Endpoints, S3 Bucket References, Firebase RTDB URLs, Internal IP Addresses, Source Map References, WebSocket Endpoints, IDOR-prone API Patterns |
| 🔵 LOW      | Sensitive Code Comments (TODO/FIXME/password), Debug Mode Flags, `console.log` leaking sensitive data |
| ⚪ INFO     | API Endpoints, Email Addresses, Version Strings, Staging URLs, CORS Configuration |

---

## Installation

```bash
git clone https://github.com/Richunt3r/JuicyJS.git
cd JuicyJS
python3 juicyjs.py --help
```

No `pip install` needed — JuicyJS uses only the Python standard library.

**Optional** — for better context on minified JS files:
```bash
pip install jsbeautifier
js-beautify bundle.min.js > bundle.js
python3 juicyjs.py bundle.js
```

---

## Usage

```
python3 juicyjs.py [folder/file] [options]
```

### Basic Examples

```bash
# Scan an entire folder of JS files (recursive)
python3 juicyjs.py /path/to/js-files/

# Feed a .txt file of JS URLs — JuicyJS fetches and scans each one
python3 juicyjs.py urls.txt

# Feed a .txt file that is saved JS content (wrong extension)
python3 juicyjs.py saved_script.txt

# Mix a folder with a URL list at the same time
python3 juicyjs.py ./js/ urls.txt

# Only show HIGH and CRITICAL findings (less noise)
python3 juicyjs.py ./js/ --min-severity HIGH

# Generate a shareable HTML report
python3 juicyjs.py ./js/ --output report.html

# Export findings as JSON
python3 juicyjs.py ./js/ --json findings.json

# Show full impact description for every finding
python3 juicyjs.py ./js/ --verbose

# Show more surrounding code (default is 2 lines)
python3 juicyjs.py ./js/ --context 5

# Filter by tag — e.g. only AWS and credential findings
python3 juicyjs.py ./js/ --tags aws credentials

# List all 44+ detection patterns
python3 juicyjs.py --list-patterns
```

### .txt File Behaviour

JuicyJS automatically detects what a `.txt` file contains:

| `.txt` content | What JuicyJS does |
|----------------|-------------------|
| Lines that are mostly URLs (`http://...`) | Fetches each URL and scans the JS response |
| JavaScript code saved with `.txt` extension | Scans directly as JS content |

This means you can pipe output from recon tools directly:
```bash
# Collect JS URLs with gau / waybackurls
echo "target.com" | gau --ft js > js_urls.txt
python3 juicyjs.py js_urls.txt

# Or with hakrawler
echo "https://target.com" | hakrawler -js | grep "\.js" > js_urls.txt
python3 juicyjs.py js_urls.txt
```

### All Options

```
positional arguments:
  targets               Folder(s) or JS file(s) to analyze

options:
  -h, --help            Show this help message and exit
  --min-severity, -s    Minimum severity: CRITICAL HIGH MEDIUM LOW INFO (default: INFO)
  --context, -c N       Lines of context around each match (default: 2)
  --verbose, -v         Show full impact/description for every finding
  --no-color            Disable ANSI color output (useful for piping)
  --no-banner           Skip the ASCII banner
  --json FILE           Export findings to JSON file
  --output, -o FILE     Output file — .html or .json auto-detected from extension
  --tags TAG [TAG ...]  Only show findings with these tags
  --list-patterns       List all detection patterns and exit
```

---

## Output

### Terminal Output

Each finding shows:
```
[CRITICAL]  AWS Access Key ID
  File  : /js/app.bundle.js:142
  Value : AKIAIOSFODNN7EXAMPLE
  Impact: AWS Access Key ID found. Steps: (1) Check paired secret key nearby.
          (2) Run: aws sts get-caller-identity. (3) List IAM permissions to
          determine blast radius.
  Tags  : aws  credentials  cloud
  ─────── context ───────
   140  const config = {
   141    region: "us-east-1",
▶  142    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
   143    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
   144  };
```

### HTML Report

Run with `--output report.html` to get a standalone dark-themed HTML report with:
- Severity statistics at the top
- Filter buttons to show/hide findings by severity
- Full code context for every finding
- Impact descriptions and tags
- Easy to share with program triagers

### JSON Export

Run with `--json findings.json` for machine-readable output:
```json
[
  {
    "file": "app.bundle.js",
    "pattern": "AWS Access Key ID",
    "severity": "CRITICAL",
    "value": "AKIAIOSFODNN7EXAMPLE",
    "line": 142,
    "tags": ["aws", "credentials", "cloud"],
    "description": "..."
  }
]
```

---

## Workflow for Bug Bounty

1. **Collect JS files** from the target (browser DevTools → Sources, or tools like `gau`, `waybackurls`, `hakrawler`)
2. **Run JuicyJS** against the folder
3. **Review CRITICAL/HIGH** findings first with `--min-severity HIGH`
4. **Verify each finding** using the Impact description as your guide
5. **Generate HTML report** with `--output report.html` to keep organized notes
6. **Submit report** with file name, line number, value found, and verified impact

### Pro Tips

- If files are minified (one giant line), beautify them first:  
  `js-beautify bundle.min.js -o bundle_pretty.js`
- When you see a **Source Map** finding, download the `.map` file — it contains the original unminified source
- Use `--tags idor` to quickly find all IDOR-prone endpoint patterns
- Use `--tags aws` to focus on cloud credential findings
- Pipe `--no-color --json` output into other tools for automation

---

## Supported File Types

`.js` `.jsx` `.ts` `.tsx` `.mjs` `.cjs` `.vue` `.svelte` `.txt`

`.txt` files are special: auto-detected as either a **URL list** (fetches each URL) or **JS content** (scanned directly).

---

## Legal Disclaimer

JuicyJS is intended for **authorized security testing only**.  
Use it only on targets you have explicit permission to test, such as:
- Bug bounty programs (HackerOne, Bugcrowd, Intigriti, etc.)
- Your own applications
- CTF challenges
- Authorized penetration testing engagements

Unauthorized use against systems you do not own or have permission to test is illegal and unethical.

---

## Author

**Vivek Goswami**  
LinkedIn: [linkedin.com/in/vivekgoswmii](https://www.linkedin.com/in/vivekgoswmii)  
GitHub: [github.com/Richunt3r](https://github.com/Richunt3r)

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

Found a new secret pattern in the wild? Got a real bounty using JuicyJS?  
Pull requests are welcome! To add a new detection pattern, add an entry to the `PATTERNS` list in `juicyjs.py` following the existing format.

---

<p align="center">Made for the bug bounty community 🐛</p>
