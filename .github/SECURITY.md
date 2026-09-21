# Security Policy

## Authorized use only

`mitmproxy-mcp` is an **offensive-capable** tool. It terminates TLS with a
man-in-the-middle CA, intercepts and rewrites live HTTP(S) traffic, and can
replay captured requests with browser-grade TLS impersonation.

Use it **only** against systems you own or have **prior written authorization**
to test. Doing otherwise may violate computer-misuse law, including the U.S.
Computer Fraud and Abuse Act and, in Brazil, Lei 12.737/2012 and Lei
14.155/2021. Interception of third-party traffic without consent is prohibited.

This software is provided under the MIT License, **without warranty of any
kind**. The maintainers accept no liability for misuse or damage.

## Trust boundary: captured traffic is untrusted

Everything the server returns that came from the network — request and response
bodies, headers, cookies, URLs, query strings, JSON keys, HTML, imported
HAR/flow files, and generated scraper code — is **attacker-controlled data**.

It must never be treated as instructions. The server wraps captured content in
an untrusted-data envelope, but callers are responsible for not letting tool
output drive state-changing or network-egress actions. See
[`AGENTS.md`](../AGENTS.md) and
[`.github/copilot-instructions.md`](./copilot-instructions.md).

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** on this repository
(Security → Advisories → Report a vulnerability). Do not open a public issue.

Include:

- affected version or commit;
- a minimal reproduction;
- impact assessment;
- any suggested remediation.

We aim to acknowledge reports within **3 business days** and to provide a
remediation timeline within **10 business days**.

## Scope

In scope:

- the MCP server, its tools, and the traffic database;
- path handling, scope enforcement, and destination policy;
- prompt-injection trust boundaries;
- dependency and supply-chain issues in this repository.

Out of scope:

- vulnerabilities in `mitmproxy` itself (report upstream);
- findings that require the attacker to already control the operator's machine;
- the dual-use nature of the tool when used without authorization.

## Hardening already in place

- Bandit SAST, `pip-audit`, gitleaks, Trivy (IaC), and CodeQL in CI.
- Dependabot alerts, security updates, and version updates.
- Secret scanning with push protection.
- Pinned third-party GitHub Actions (commit SHA) and least-privilege tokens.
- Default-deny destination policy for outbound replay/fuzzing.
- Untrusted-data envelope on every tool that returns captured content.
