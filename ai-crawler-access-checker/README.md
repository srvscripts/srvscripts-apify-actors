# Bulk AI Crawler Access Checker

Check how a whole list of domains treats AI crawlers — in one run. For each domain this Actor reports:

- **robots.txt AI-bot policy** — allowed or blocked for **GPTBot, OAI-SearchBot, ClaudeBot, PerplexityBot, CCBot, Amazonbot**, plus the **Google-Extended** and **Applebot-Extended** policy tokens.
- **Live User-Agent response test** — how the server *actually* answers each AI crawler's User-Agent versus a normal browser. This catches firewall / CDN blocks that robots.txt alone can't reveal: sites whose robots.txt *allows* a bot but whose edge *refuses* it anyway.
- **llms.txt, ai.txt, and RSL / Content-Usage** — presence and basic validity of the newer AI-permission files.

Read-only and safe: GET requests to the domains you enter only, redirects are never followed, and private or internal addresses are refused.

## Who it's for

Agencies, SEO/GEO teams, hosting providers and MSPs auditing AI-crawler access across many sites at once — portfolio checks, client onboarding, and monitoring whether AI assistants can actually read a site.

## Input

```json
{ "domains": ["example.com", "anotherdomain.com"] }
```

## Output (one dataset row per domain)

`domain`, `robots_state`, `policy` (per crawler), `home_baseline`, `live` (per crawler: policy + observed HTTP response + flag), `allowed_but_refused_count`, `llms_txt`, `ai_txt`, `rsl`.

The **"Allowed but refused"** count is the headline signal: how many AI bots a site's robots.txt permits but its server actually turned away.

## How to read the results — honestly

The live test runs from Apify's servers using crawler **User-Agent strings**. It shows how a site treats those User-Agents — not traffic from the crawler operators' own verified IP ranges. robots.txt is advisory, so **policy** (what robots.txt says) and **observed response** (what the server did) are always reported separately, never merged into a single verdict.

Invalid or unreachable domains are not charged.

---

Built by **srvScripts** — server and website tools for hosting professionals. https://srvscripts.com/
