# BugBiner AI

A web crawling and security testing platform with a live interface for monitoring scans and reviewing results with optional AI-assisted analysis. The project is under active development; results may vary depending on the target, its accessibility, configuration, and application type.

> **Legal notice:** Use this tool only on systems you own or have explicit permission to test. Active scans send test requests to the target and may affect its performance or data. Start with a limited scope, obtain the system owner's approval, and do not use sensitive production data.

## Overview

The project consists of:

- **Python and FastAPI server** for managing scans and settings and serving the interface.
- **Node.js and Puppeteer crawler** for opening website pages and discovering links and input points.
- **Web interface** for monitoring crawling, results, and a live site map.
- **Scanning engines** for testing different types of web security issues, with optional AI-assisted analysis.
- **`reports/` directory** for storing HTML reports and scan result data.

## Features

- Interactive website crawling to collect reachable pages and input points.
- Scan scope selection: current host, domain with subdomains, or specified subdomains.
- Select vulnerability types from the interface catalog instead of necessarily running every type.
- Live scan events and findings, with a site map and asset dashboard.
- Pause and resume a scan, or stop it, with progress state saved for continuation.
- Review finding details and request AI analysis or PoC generation when the feature and required connection are available.
- Configure and test AI providers and models from **AI Settings**, and manage Ollama models.
- Browser-based DOM/XSS checks and selected advanced modules, subject to their requirements and dependencies.
- Generate HTML reports and save scan results locally in `reports/`.
- Browse project files and manage local files through the interface.

### Vulnerability check catalog

The bundled catalog currently contains **40 check types**. This is the number of types registered in the catalog; it does not guarantee that each type will be tested or detected on every website. Testing depends on the target, discovered pages and input points, configuration, and available modules and dependencies.

| Category | Examples |
|---|---|
| Injection | XSS, SQL Injection, NoSQL Injection, SSTI, Command Injection, LFI/Path Traversal, XXE, LDAP and XPath Injection |
| Requests, headers, and caching | SSRF, Open Redirect, Host Header Injection, CRLF, HTTP Parameter Pollution, Web Cache Poisoning, HTTP Request Smuggling |
| Browser and client-side | DOM XSS, CSRF, Clickjacking, CORS, WebSocket, File Upload, Prototype Pollution |
| Access control and identity | IDOR/BOLA, Broken Access Control, JWT, GraphQL, Mass Assignment, Rate Limiting |
| Configuration, information, and business logic | Information and secret exposure, Subdomain Takeover, Security Headers, TLS/HSTS, Race Conditions, Business Logic, and LLM risks |

The application displays the current list and version from `backend/vuln_catalog.json`. The checks do not all use the same verification method, and some may not be applicable to a given target.

## AI and privacy

The application supports multiple providers, including:

- **Ollama** for running a local model.
- **OpenAI-compatible APIs**, as well as Anthropic, Google Gemini, and Z.AI.

Choosing a cloud provider sends requests or the context needed for analysis to that provider, subject to its configuration and privacy policy. Do not assume the application operates entirely locally when a cloud service is selected. Do not put API keys in a public repository; `config.json` contains local settings and is excluded from Git.

The server does not automatically download or load a model at startup. Choose a provider and model in **AI Settings**, and configure the model or API key before using AI analysis features.

## Requirements

- Windows 10 or 11.
- Python 3.12 or later.
- Node.js LTS and npm.
- Ollama if you want to run a local model. `start.bat` also checks for and starts Ollama.
- An internet connection when installing dependencies, using a cloud AI provider, or using external features such as OAST.

## Installation and startup on Windows

### Quick start

1. Download and extract the project.
2. Run `start.bat`.
3. If needed, the script attempts to install Python, Node.js, or Ollama using `winget`, then creates a virtual environment and installs the Python and Puppeteer dependencies.
4. Once dependencies are ready, the server starts on port `9090` and opens the browser.

Installation may require permission to install software and an internet connection. If `winget` is unavailable or automatic installation fails, install the requirements manually and run the script again.

### Starting after setup

You can use `start.ps1` to launch the server and open the interface after the virtual environment has already been prepared:

```powershell
.\start.ps1
```

Once the server is running, open:

<http://localhost:9090>

## How to use

1. Open **AI Settings** and select an AI provider and model if you want AI-assisted features.
2. Enter the URL of a website you are authorized to test.
3. Choose the scan scope and check types. Use the smallest appropriate scope.
4. Click **Start Scan** to monitor crawling and scanning in the interface.
5. Review pages, findings, and evidence manually; a tool result is not definitive proof of a vulnerability.
6. Request analysis or a PoC when needed, then review the HTML report and scan results in `reports/`.
7. Use **Pause/Resume** to pause or continue, or **Stop** to end the scan.

## Important files and directories

| Path | Purpose |
|---|---|
| `backend/main.py` | FastAPI server and application endpoints |
| `backend/crawler.js` | Puppeteer crawler |
| `backend/detect_engine.py` and other scan modules | Detection logic and supporting modules |
| `backend/vuln_catalog.json` | Vulnerability check catalog |
| `frontend/` | Web interface files |
| `config.json` | Local AI settings; do not share if it contains an API key |
| `reports/` | HTML reports and scan result data |
| `tools/` | Optional tools, including the Interactsh client for OAST features |

## Limitations and notes

- The project is under development; some checks may be experimental or unsuitable for certain applications.
- A check listed in the catalog does not guarantee that the engine can run a valid test for it in every case.
- Active scans and OAST features may contact the target or external services. Use them only with authorization and configure the scope carefully.
- AI is an analysis aid, not a replacement for manual verification or qualified security review.
- Do not enter real credentials or sensitive information into requests or project files without understanding where it is stored and which services may receive it.

## Links

- Demo video: <https://www.youtube.com/watch?v=exnomF4Ccn4>
- Repository: <https://github.com/joudi-janble/BugBiner-AI>

## License

Review the license files included with the project and any external tools in the `tools/` directory. Use of the project must comply with applicable laws and license terms.
