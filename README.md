# srvScripts — Apify Actors

Server tools that scale. We build free single-site tools at
[srvscripts.com](https://srvscripts.com) and publish their **bulk** versions
here as Apify Actors, for agencies and MSPs auditing many domains at once.

All Actors are **read-only** and use **DNS / HTTP only** — passive checks, no
exploit attempts, no logins, no writes. Run them only on domains you own or
manage.

## Actors

| Actor | What it does | Apify |
|---|---|---|
| **AI Crawler Access Checker** | robots.txt AI rules, llms.txt, ai.txt, RSL licensing, plus a live User-Agent response test, across a whole domain list. | [srvscripts/ai-crawler-access-checker](https://apify.com/srvscripts/ai-crawler-access-checker) |
| **Bulk Hosting & PHP-CVE Exposure Auditor** | Detects out-of-date, CVE-exposed PHP (incl. the Oct 2026 "php2shell" CVEs), web server, WAF/CDN and CMS across a whole domain list. Passive fingerprinting only. | [srvscripts/hosting-php-cve-auditor](https://apify.com/srvscripts/hosting-php-cve-auditor) |

### Coming soon
- Bulk email-domain health (SPF / DKIM / DMARC / MTA-STS / BIMI)
- Bulk SSL/TLS & certificate expiry

## Repository layout

```
ai-crawler-access-checker/   # Actor source (.actor/, main.js, Dockerfile, package.json)
hosting-php-cve-auditor/     # Actor source
```

Each subfolder is a self-contained Apify Actor. Its own `README.md` documents
input, output and the detection baseline.

## Building

Each Actor is Node (ESM) on the `apify/actor-node:20` base image.

```bash
cd hosting-php-cve-auditor
npm install
apify run          # local run
apify push         # deploy to Apify
```

To build from this repo instead of `apify push`: in the Actor's
**Settings → Source**, point it at this Git repository and set the folder to
the Actor's subfolder.

## Safety & accuracy

These tools report what a server discloses from the outside. Version detection
is best-effort: a server can hide or spoof a banner, and a WAF can shield an
unpatched origin — so a result is a strong hint to confirm on the server, not a
guarantee. Nothing here sends a payload or attempts access.

---

Built by **srvScripts** · [srvscripts.com](https://srvscripts.com)
