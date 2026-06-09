# aiopsone-assure

> **APRA compliance evidence for AWS, from your terminal.** Point `assure` at an AWS account (or existing Prowler findings) and get a **board-ready, APRA-paragraph-mapped narrative report** (Markdown + branded PDF) for **CPS 234** and **CPS 230** — generated locally, in your own environment.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/jaybilgaye/aiopsone-assure/actions/workflows/ci.yml/badge.svg)](https://github.com/jaybilgaye/aiopsone-assure/actions/workflows/ci.yml)

**Keywords:** APRA CPS 234 / CPS 230 · AWS compliance report · Prowler findings to board narrative · Bedrock AI compliance · Australian regulated cloud

---

## Why

Security scanners produce **findings**. Boards and APRA want **narrative evidence** — "demonstrate, mapped to CPS 234 ¶21, that information assets are encrypted, with evidence and a remediation plan." That translation is the biggest time-sink in an APRA review.

`assure` closes the gap: **findings → CPS 234/230 paragraph mapping → board-ready narrative report.** It runs entirely in your environment — your AWS credentials, your Bedrock, nothing leaves your account.

📖 Write-up: [Assure — an open-source CLI for APRA compliance reports on AWS](https://aiopsone.com/blog/assure-apra-compliance-cli)

> Built on **Prowler**, **Powerpipe**, **Cloud Custodian** and **AWS Config** — the best open-source scanners. `assure` does the part they don't: turning their findings into APRA-paragraph board evidence.

## Install

```bash
pipx install aiopsone-assure          # or: pip install aiopsone-assure
pipx install "aiopsone-assure[ai]"    # + Bedrock AI narrative (boto3)
pipx install "aiopsone-assure[scan]"  # + run Prowler scans (prowler)
```

PDF output needs Chrome/Chromium on the machine (set `$ASSURE_CHROME` to override the path), or use `--format md`.

## Usage

```bash
# 1. Run Prowler against an account and build the report in one step
assure scan --framework cps234 --region ap-southeast-2

# 2. Build a report from findings you already have (Prowler CSV / JSON / OCSF)
assure report --in findings.csv --framework cps234

# 3. Deterministic, no AI (template engine — default; zero AWS calls)
assure report --in findings.csv --no-ai

# 4. AI narrative via Amazon Bedrock (AU-resident), board-ready PDF
assure report --in findings.csv --engine bedrock --region ap-southeast-2 --format pdf

# 5. CI gate: non-zero exit if any control FAILs; machine-readable summary
assure report --in findings.csv --json
```

List bundled frameworks:

```bash
assure frameworks
# cps234   APRA CPS 234 Information Security  (20 controls, 55 checks)
# cps230   APRA CPS 230 Operational Risk Management  (18 controls, 15 checks)
```

## What you get

A board-ready report with:
- **Executive summary** + automated compliance score
- **Control-by-control assessment** mapped to CPS 234/230 paragraphs (PASS / FAIL / MANUAL / NOT-ASSESSED)
- **Cited evidence** per failing control
- **Remediation roadmap**

Two formats: **Markdown** (always) and a **branded PDF** (professional, print-friendly).

## How it works

```
 AWS account / existing findings
        │  (your own AWS creds — nothing leaves your environment)
        ▼
   assure ── run Prowler (scoped to the framework's checks)
        │
        ├─ map check → CPS 234/230 paragraph   (we own the mapping; no FW injection into Prowler)
        ├─ narrate: template (offline) or Amazon Bedrock / Claude (AU-resident)
        ▼
   Board-ready report: Markdown + branded PDF
```

## Exit codes

`0` no failing controls · `2` one or more controls FAIL (for CI gating) · `1` error. Use `--exit-zero` to always return 0.

## Frameworks are pluggable

A framework is just data — a pack JSON mapping checks → paragraphs. Bundled: CPS 234, CPS 230. Point `--framework path/to/pack.json` at your own. (Roadmap: Essential Eight, ACSC ISM/IRAP, then ISO 27001 / SOC 2.)

## Status & scope

v0.1 — CLI. Self-hosted, single-shot, stores nothing. The hosted SaaS (continuous, multi-account, managed AU-resident inference, dashboard) is a separate product that wraps this engine.

---

*Practitioner tooling for AWS Security in APRA-regulated Australia — [aiopsone.com](https://aiopsone.com). Not legal advice; verify against the official APRA standards.*
