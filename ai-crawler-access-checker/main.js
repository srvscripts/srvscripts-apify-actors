// Bulk AI Crawler Access Checker — Apify Actor
// For each domain: reads its AI-policy files (robots.txt AI rules, llms.txt, ai.txt, RSL)
// and runs a live User-Agent response test (how the server answers each AI crawler's UA vs a
// normal browser), from Apify's servers. Read-only: GET requests only, redirects never followed.
// Ported from srvScripts' on-site AI Crawler Access Checker. https://srvscripts.com/

import { Actor } from 'apify';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import net from 'node:net';

const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36';
const AI_UAS = {
    GPTBot: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot',
    'OAI-SearchBot': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot',
    ClaudeBot: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ClaudeBot/1.0; +claudebot@anthropic.com',
    PerplexityBot: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot',
    CCBot: 'CCBot/2.0 (https://commoncrawl.org/faq/)',
    Amazonbot: 'Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)',
};
// Policy-only control tokens (no fetcher of their own): robots verdict, no live HTTP test.
const POLICY_ONLY = ['Google-Extended', 'Applebot-Extended'];

function isPrivateIp(ip) {
    if (net.isIPv4(ip)) {
        const o = ip.split('.').map(Number);
        return o[0] === 10 || o[0] === 127 || (o[0] === 169 && o[1] === 254) ||
            (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) || o[0] === 0 || o[0] >= 224;
    }
    const l = ip.toLowerCase();
    return l === '::1' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l.startsWith('::ffff:');
}

async function hostIsPublic(host) {
    try {
        const addrs = await dns.lookup(host, { all: true });
        if (!addrs.length) return false;
        return !addrs.some((a) => isPrivateIp(a.address));
    } catch { return false; }
}

// One GET, never follows redirects. Resolves { code, bytes, ct, body, err }.
function fetchNoRedirect(url, ua, timeoutMs = 8000, maxBytes = 120000) {
    return new Promise((resolve) => {
        let u;
        try { u = new URL(url); } catch { return resolve({ code: 0, bytes: 0, ct: '', body: '', err: 'bad url' }); }
        const lib = u.protocol === 'http:' ? http : https;
        const req = lib.request(u, { method: 'GET', headers: { 'User-Agent': ua, Accept: '*/*' }, timeout: timeoutMs }, (res) => {
            const code = res.statusCode || 0;
            const ct = String(res.headers['content-type'] || '');
            let len = 0; const chunks = [];
            res.on('data', (c) => { len += c.length; if (len <= maxBytes) chunks.push(c); else res.destroy(); });
            res.on('end', () => resolve({ code, bytes: len, ct, body: Buffer.concat(chunks).toString('utf8'), err: '' }));
            res.on('aborted', () => resolve({ code, bytes: len, ct, body: Buffer.concat(chunks).toString('utf8'), err: '' }));
        });
        req.on('timeout', () => { req.destroy(); resolve({ code: 0, bytes: 0, ct: '', body: '', err: 'timeout' }); });
        req.on('error', (e) => resolve({ code: 0, bytes: 0, ct: '', body: '', err: e.message }));
        req.end();
    });
}

function classify(r) {
    const { code, bytes, body } = r;
    if (!code) return 'noresponse';
    if (code >= 300 && code < 400) return 'redirect';
    if (code === 401 || code === 403) return 'refused';
    if (code === 429) return 'ratelimited';
    if (code === 404 || code === 410) return 'notfound';
    if (code >= 400 && code < 500) return 'clienterror';
    if (code >= 500) return 'servererror';
    if (code >= 200 && code < 300) {
        if (code === 204 || bytes === 0) return 'empty';
        if (bytes < 15000 && /just a moment|cf-chl|challenge-platform|cf-browser-verification|attention required|verifying you are human|enable javascript and cookies|hcaptcha|g-recaptcha|px-captcha/i.test(body.slice(0, 8000))) return 'challenge';
        return 'served';
    }
    return 'servererror';
}

// --- robots.txt parsing (RFC 9309, faithful to the on-site tool) ---
function robotsParse(txt) {
    const groups = []; let cur = null; let uaRun = false;
    for (let line of String(txt).split(/\r\n|\r|\n/)) {
        line = line.replace(/#.*$/, '').trim(); if (!line) continue;
        const m = line.match(/^([A-Za-z-]+)\s*:\s*(.*)$/); if (!m) continue;
        const k = m[1].toLowerCase(); const v = m[2].trim();
        if (k === 'user-agent') { if (!uaRun || cur === null) { groups.push({ agents: [], rules: [] }); cur = groups.length - 1; } groups[cur].agents.push(v.toLowerCase()); uaRun = true; continue; }
        uaRun = false;
        if ((k === 'allow' || k === 'disallow') && cur !== null) groups[cur].rules.push([k, v]);
    }
    return groups;
}
function robotsRules(groups, ua) {
    ua = ua.toLowerCase(); let named = []; let star = []; let isNamed = false;
    for (const g of groups) for (const a of g.agents) {
        if (a === '*') star = star.concat(g.rules);
        else if (a === ua) { named = named.concat(g.rules); isNamed = true; }
    }
    return [named.length ? named : star, isNamed];
}
function robotsAllowed(rules, path) {
    let best = null; let blen = -1;
    for (const [k, pat] of rules) {
        if (!pat) continue;
        const end = pat.endsWith('$'); const p2 = end ? pat.slice(0, -1) : pat;
        const re = new RegExp('^' + p2.replace(/[.*+?^${}()|[\]\\]/g, (c) => (c === '*' ? '.*' : '\\' + c)) + (end ? '$' : ''));
        if (re.test(path)) { const len = pat.length; if (len > blen || (len === blen && k === 'allow')) { best = [k, pat]; blen = len; } }
    }
    return !best || best[0] === 'allow';
}

async function auditDomain(input) {
    const host = String(input).trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
    const out = { domain: host, ok: false };
    if (!host || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) { out.error = 'invalid domain'; return out; }
    if (!(await hostIsPublic(host))) { out.error = 'does not resolve to a public address'; return out; }
    const base = `https://${host}/`;

    // robots.txt (no redirect, up to 512KB)
    const rob = await fetchNoRedirect(base + 'robots.txt', BROWSER_UA, 8000, 512000);
    const rclass = classify(rob);
    let robotsState = 'error'; let groups = [];
    if (rclass === 'served' || rclass === 'empty') { groups = robotsParse(rob.body); robotsState = 'ok'; }
    else if (rclass === 'notfound') robotsState = 'missing';
    else if (rclass === 'redirect') robotsState = 'redirect';
    out.robots_state = robotsState;
    out.robots_truncated = rob.bytes >= 512000;

    const verdict = (tok) => {
        if (robotsState === 'missing') return ['allowed', false];
        if (robotsState !== 'ok') return ['unknown', false];
        const [rules, named] = robotsRules(groups, tok);
        return [robotsAllowed(rules, '/') ? 'allowed' : 'blocked', named];
    };

    // Policy table (all tokens)
    out.policy = {};
    for (const tok of [...Object.keys(AI_UAS), ...POLICY_ONLY]) { const [v, named] = verdict(tok); out.policy[tok] = { policy: v, named_explicitly: named }; }

    // Live UA test (only if browser baseline is a real content response)
    const baseline = await fetchNoRedirect(base, BROWSER_UA);
    const baseClass = classify(baseline);
    out.home_baseline = `${baseClass} (HTTP ${baseline.code})`;
    out.live = {};
    let allowedRefused = 0;
    if (baseClass === 'served') {
        for (const [tok, ua] of Object.entries(AI_UAS)) {
            const r = await fetchNoRedirect(base, ua);
            const c = classify(r);
            const [v] = verdict(tok);
            let flag = 'inconclusive';
            if (c === 'served') flag = (v === 'blocked') ? 'served_despite_robots' : 'ok';
            else if (c === 'redirect') flag = 'redirect_not_tested';
            else if (c === 'empty') flag = 'no_content';
            else if (c === 'refused') { if (v === 'allowed') { flag = 'refused_though_allowed'; allowedRefused++; } else flag = 'refused'; }
            out.live[tok] = { policy: v, observed: `${c} (HTTP ${r.code})`, flag };
        }
    } else {
        out.live_note = `live test not run — home page returned ${baseClass} to a normal browser`;
    }
    out.allowed_but_refused_count = allowedRefused;

    // llms.txt
    const llm = await fetchNoRedirect(base + 'llms.txt', BROWSER_UA);
    const lc = classify(llm);
    if (lc === 'served') {
        const isHtml = /text\/html/i.test(llm.ct) || /^\s*<(!doctype|html)/i.test(llm.body);
        const first = (llm.body.split(/\r\n|\r|\n/).find((l) => l.trim()) || '').trim();
        const looks = /^#\s+\S/.test(first) || /^\s*[-*]\s*\[[^\]]+\]\(\S+\)/m.test(llm.body);
        out.llms_txt = isHtml ? 'html_page' : (looks ? 'present' : 'unverified');
    } else out.llms_txt = (lc === 'notfound' || lc === 'clienterror') ? 'not_found' : (lc === 'empty' ? 'empty' : lc);

    // ai.txt (anchored directives)
    out.ai_txt = 'not_found';
    for (const cand of ['ai.txt', '.well-known/ai.txt']) {
        const a = await fetchNoRedirect(base + cand, BROWSER_UA);
        const ac = classify(a);
        if (ac === 'served' && !/text\/html/i.test(a.ct) && !/^\s*<(!doctype|html)/i.test(a.body)) {
            out.ai_txt = /^\s*(user-agent|disallow|allow)\s*:/im.test(a.body) ? 'present' : 'unverified'; break;
        } else if (['refused', 'ratelimited', 'servererror', 'noresponse', 'challenge'].includes(ac)) out.ai_txt = 'could_not_check';
    }

    // RSL / usage terms
    out.rsl = 'not_detected';
    for (const cand of ['rsl.xml', '.well-known/rsl.xml', 'license.xml']) {
        const x = await fetchNoRedirect(base + cand, BROWSER_UA);
        if (classify(x) === 'served' && !/text\/html/i.test(x.ct)) {
            const head = x.body.replace(/^\s+/, '').slice(0, 4000);
            if (/^(<\?xml[^>]*\?>\s*)?<rsl[\s>]/i.test(head) || /rslstandard\.org/i.test(head)) { out.rsl = `served:${'/' + cand}`; break; }
        }
    }
    const rterms = String(rob.body || '').match(/^\s*(content-signal|content-usage|license)\s*:\s*(.+)$/im);
    if (out.rsl === 'not_detected' && rterms) out.rsl = `robots:${rterms[1].toLowerCase()}`;

    out.ok = true;
    return out;
}

await Actor.init();
const { domains = [] } = (await Actor.getInput()) || {};
const list = (Array.isArray(domains) ? domains : String(domains).split(/[\s,]+/)).map((d) => String(d).trim()).filter(Boolean);
if (!list.length) { await Actor.fail('No domains provided. Give a "domains" list.'); }

let charged = 0;
for (const d of list) {
    const row = await auditDomain(d);
    // Pay-per-event: charge only for a domain that returned a usable result (configure the event + price in the Store).
    if (row.ok) { try { await Actor.charge({ eventName: 'domain-checked' }); charged++; } catch { /* charging disabled in local/dev runs */ } }
    await Actor.pushData(row);
}
await Actor.setValue('SUMMARY', { domains: list.length, checked: charged });
await Actor.exit();
