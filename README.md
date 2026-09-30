# Threat Recap

A free, ad-free cybersecurity news and threat-intel page. It pulls the latest headlines, threat-intel reports, CVEs, breaches, APT activity, zero-days, ransomware claims, IOCs and malicious packages from **103 feeds and 9 data sources** into one searchable page, so nobody has to check dozens of sites every morning.

No accounts, no tracking (unless you turn on privacy-friendly GoatCounter), no paid tier. Every headline links to the original article.

## Features

**Daily reading**
- **Morning brief**: what changed since your last visit (new exploited CVEs, zero-days, breaches, ransomware claims, stories about your stack, and "on this day" in security history).
- **Headlines with time posted**: newest first, grouped by day, auto-refreshing, with a "↑ N new" button.
- **Story merging**: the same story from many outlets is shown once, as "N sources".
- **Search bar**: as-you-type search with highlighting, plus `"phrases"`, `cve:`, `actor:`, `vendor:`, `malware:`, `source:`, `tag:` and `attack:` filters. Searches are shareable URLs.
- **Command palette** (`Ctrl/⌘+K`): jump to any tab, actor, vendor, ransomware group, malware family, CVE or source.
- **Sections** (left sidebar): Latest · My stack · Saved · Zero-days · Breaches · Ransomware · APT · Malware · Supply chain · CVEs · IOCs · Research · Advisories · Topics · Categories · Trends · Patch Tuesday · Sources.
- **Three layouts**: Cards (with preview images), List (one line per story, feed-reader style) and Grid.
- **Site icons, preview images and category badges** on every story (`app`, `exp`, `net`, `mal`, `cloud`, `ics`, `id`, `dfir`…).
- **Topics**: every product, vendor, threat actor and malware family as a #hashtag with 24h / 7d / 30d counts. Type `#NetScaler` in search.
- **Categories**: stories by technical area (application security, exploit development, cloud, ICS/OT, identity…). Search with `cat:exp`.

**Personal (stored in the browser only)**
- **Hide**: a Hide button on every story hides that story, everything from its source, or a topic (e.g. all Oracle stories), with Undo. Manage the list in Settings.
- **My stack**: pick your vendors and keywords in ⚙ Settings. Matching stories get a ★ everywhere and their own tab, which also shows actively exploited CVEs in your products.
- **Save / watchlist**: a ＋ Save button beside every headline. You get an **Updated** badge when more outlets cover a saved story or its CVE lands in CISA KEV.
- **Notifications**: alerts for new zero-days, new KEV entries, your stack and saved-story updates. They work while a tab is open; if the site is installed as an app in Chrome/Edge, it also checks in the background about hourly.
- **Headline translation**: uses the browser's built-in on-device translator where available (Chrome), otherwise offers Google Translate.
- **Read tracking**, light/dark theme, installable app, works offline, keyboard shortcuts (`?`).

**Vulnerabilities**
- **How to fix**: fixed versions per product ("upgrade to 14.1-73.37 or later") and vendor advisory links from the official CVE record, plus CISA's required action for exploited CVEs.
- **Plain-English explanations** (optional, needs an Anthropic API key): what the flaw lets an attacker do, who is affected and what to do.
- **Patch first**: a to-do list ranked by real-world risk (KEV → EPSS → public exploit → news coverage → CVSS), with the reasons shown.
- **CVE panel**: CVSS, EPSS, KEV status and due date, **public PoC repos**, links to **Sigma / Nuclei / Metasploit / YARA / Suricata** rules, and related stories.
- **Top of the decade**: 54 landmark vulnerabilities since 2016 (EternalBlue, Zerologon, Log4Shell, Citrix Bleed, MOVEit, Dirty COW, PwnKit…) plus no-CVE techniques like the Potato family, with hand-written explanations and live CVSS (NVD’s own score), CISA KEV and ransomware use, EPSS and public exploit counts. Edit `landmarks.js` to add more.
- **Tenable plugins**: new Nessus, Cloud Security and Container Security checks from Tenable's public plugin feed (30-day history), split into vendor/application checks, OS package updates and open-source libraries, with checks for exploited or in-the-news CVEs flagged. Each CVE panel lists the matching plugins.
- **New exploits**: newly published PoC code for tracked CVEs (via nomi-sec/PoC-in-GitHub and Exploit-DB).
- CVEs in the news, latest KEV additions, and newly published CVEs by severity.

**Threat intel**
- **Developing stories**: incidents that keep getting coverage (e.g. a zero-day campaign) as a timeline across outlets: first report, exploitation, CISA listing, public exploit, patch and analysis. Each has a shareable page under `/stories/`.
- **Breach tracker**: the largest breaches of the period, with the number of affected records read from the reporting.
- **IOC extractor**: hashes, IPs, domains and URLs pulled from research reports, with copy buttons, VirusTotal / abuse.ch lookups and a CSV export of everything.
- **Profile pages** for **threat actors** (aliases, origin, MITRE ID, timeline, CVEs, malware, techniques), **vendors** (exploited CVEs, news timeline) and **ransomware groups** (claims chart, countries, sectors, news). These are static pages, good for search engines.
- **Trends**: rising actors, vendors, CVEs, malware and topics this week versus last; "this week in numbers" with a **downloadable share image**; this week in security history.
- **Ransomware tracker**: all-time / this-year / 30-day / 24-hour totals, a **10-day activity strip** (top groups, countries, sectors per day), an animated **world map**, a **live map** (pulsing markers for recent claims, replay in posting order, live ticker), a **countries table** (24 h / 7 d / 30 d / this year / all time, sortable), **victim cards** (flag, group, sector, domain as text, description, attack vs discovered date, matching news coverage), a **countries** table and per-group pages. Everything is clearly labelled as unverified claims.
- **Breaches**: breach news plus the newest datasets loaded into Have I Been Pwned.
- **ATT&CK chips** and **malware-family chips** (keyword-based guesses, labelled as such).
- **Optional AI "why it matters"** notes on the most-covered stories (needs an Anthropic API key; off by default).

**Archive (year to date)**
- **Archive** section: every story since January 1 (rebuilt from the Wayback Machine’s saved copies of each feed), every CVE published this year (NVD), CISA’s exploited list, all ransomware leak-site claims and all breaches loaded into Have I Been Pwned — by month, searchable across the whole year, with a coverage table per source.
- **Archived copy** links on every story and vendor advisory, in case the original changes or disappears.

**Sharing & reuse**
- **RSS feeds out**: latest, top, zero-days, KEV, breaches, APT, ransomware, supply chain, research, advisories, plus one per vendor and per actor.
- **Public JSON API**: documented on `api.html`.
- **Weekly digest**: `digest.html`, optionally emailed through Buttondown.
- **SEO**: share-preview image, sitemap, robots.txt and canonical links (set `SITE_URL`).
- **Community fixes**: a "Report" link on every story opens a pre-filled GitHub issue.

## Run it on your computer

Requires [Node.js](https://nodejs.org) 18 or newer. No `npm install` needed unless you want AI notes.

```sh
node server.js
```

Open <http://localhost:3000>. The first build takes about a minute, and the server rebuilds every 20 minutes.
To build once without the server, run `node build.js`; the output goes to `public/`.

## Put it online for free (GitHub Pages)

1. Create a **public** GitHub repository and push this folder, including `.github/`.
2. Go to **Settings → Pages** and under *Build and deployment* choose **Source: GitHub Actions**.
3. Go to **Actions → update-news → Run workflow**. After about 2 minutes the site is live at `https://<user>.github.io/<repo>/`.

It then updates itself every 20 minutes. GitHub pauses scheduled workflows in repositories with no activity for 60 days; if that happens, click *Enable workflow* in the Actions tab.

### Optional settings (Settings → Secrets and variables → Actions)

| Name | Type | What it does |
|---|---|---|
| `SITE_URL` | Variable | Your site's address, e.g. `https://you.github.io/threat-recap/`. Enables the sitemap, absolute share previews and links in the digest. |
| `NVD_API_KEY` | Secret | Free key from [NVD](https://nvd.nist.gov/developers/request-an-api-key). Makes CVE fetching faster and more reliable. |
| `ANTHROPIC_API_KEY` | Secret | Turns on one-line AI "why it matters" notes for up to 30 widely covered stories per run, using `claude-opus-5-5` at low effort (override with an `AI_MODEL` env var). That's roughly a few cents a day; leave it unset to stay completely free. |
| `GOATCOUNTER` | Variable | Your [GoatCounter](https://www.goatcounter.com) code for privacy-friendly visitor counts (no cookies). |
| `BUTTONDOWN_USER` | Variable | Your [Buttondown](https://buttondown.com) username. Shows the email signup box and enables the weekly digest workflow. |
| `BUTTONDOWN_API_KEY` | Secret | Buttondown API key, used to create the weekly email. |
| `DIGEST_AUTOSEND` | Variable | `true` sends the digest automatically. Otherwise it's saved as a draft. |

### Your own domain

Buy a domain (about $10/year), add it under **Settings → Pages → Custom domain**, follow GitHub's DNS instructions, and set `SITE_URL` to it.

## Building the archive

Run the one-time backfill once (about an hour; it is resumable and rate limited to about one request per second to archive.org):

```sh
node backfill.js          # all CVEs of the year from NVD, then every news source
node build.js             # publishes public/data/archive/
```

After that, every regular build adds what it sees, so the archive keeps growing on its own. On GitHub, run the **backfill** workflow once from the Actions tab (Actions → backfill → Run workflow); it stores the result in the same cache the regular updates use.

## Adding or fixing sources

All sources are in `sources.json`:

```json
{"name":"Example Labs","cat":"research","site":"https://example.com/blog","feed":"https://example.com/feed/"}
```

- `cat` is `research`, `news`, `advisory`, `tool` (a link-only entry).
- `"filter": true` keeps only security-related posts from general-tech feeds.
- `"bulk": true` marks high-volume advisory feeds. These appear in *Advisories*, *CVEs* and search, but not in *Latest*.

Threat actors (aliases, origin, MITRE IDs) and malware families are in `actors.js`; tagging rules, vendors and ATT&CK keywords are in `taxonomy.js`. The **Sources** tab shows each feed's health.

## How it works

```
sources.json ─► build.js ─► public/data/news.json      stories (tagged, merged, AI notes)
CISA KEV · NVD · CVE.org · EPSS ─►   cves.json          KEV, CVSS, EPSS, new CVEs
PoC-in-GitHub · Exploit-DB ─────►   cves.json (poc)     public exploit code
research articles ─────────────►    iocs.json           extracted indicators
ransomware.live ───────────────►    ransomware.json     claims, stats, per-country days
Have I Been Pwned ─────────────►    breaches.json
GitHub Advisory Database ──────►    supply.json
world-atlas ───────────────────►    world.json          map shapes (built once)
                     site.js ─► public/actors|vendors|groups/*.html, feeds/*.xml, sitemap.xml
                   digest.js ─► public/digest.html
public/index.html + app.js read those files; no server code or database.
```

`cache/` keeps 30 days of history, CVE scores, PoC lookups, IOCs and AI notes between runs (GitHub Actions stores it with `actions/cache`).

## Notes

- Tags, actors, vendors, malware, ATT&CK techniques and IOCs are automated extraction and can be wrong. Treat them as pointers, and verify IOCs before blocking.
- Ransomware data are claims posted by criminal groups on leak sites; they're often exaggerated or recycled. Victim sites and leak-site links are never shown.
- Exploit repositories are untrusted code. Read them before running, and only in a lab.
- The site shows only headlines and short feed summaries and always links to the publisher. For research posts without a full feed, the build fetches the article once to look for IOCs and stores only the indicators. If a publisher asks to be removed, delete it from `sources.json`.
- AI notes are generated only from the headline and summary, and are marked as AI-generated on the page.

## Credits

Feeds for Black Hills InfoSec, LevelBlue SpiderLabs, Apple and Adobe security bulletins, and IFIN analysis come from the public [IFIN news feed](https://news.ifin.network/) because those publishers have no RSS of their own. Site icons come from DuckDuckGo's icon service and flags from the [flag-icons](https://github.com/lipis/flag-icons) project; both are fetched at build time and served from this site.
