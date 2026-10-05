# Threat Recap: setup and development

How to run Threat Recap yourself, put it online and change its sources. For what the site does, see the [README](../README.md).

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

The workflow has its own schedule, but GitHub runs scheduled workflows on a best-effort basis: on a new repository they were often hours late or skipped. For reliable updates, use a free external timer such as [cron-job.org](https://cron-job.org) to start the workflow (the live site uses one, every 30 minutes):

1. Create a fine-grained token at <https://github.com/settings/personal-access-tokens/new>: *Only select repositories* → this repository; *Repository permissions* → **Actions: Read and write**; nothing else.
2. Create a cron job that sends a `POST` to `https://api.github.com/repos/<user>/<repo>/actions/workflows/update-news.yml/dispatches` with the headers `Authorization: Bearer <token>`, `Accept: application/vnd.github+json` and `Content-Type: application/json`, and the body `{"ref":"main"}`. A test run should return **204 No Content**.
3. When the token expires (GitHub emails you first), create a new one and replace it in the job's `Authorization` header.

GitHub also pauses scheduled workflows in repositories with no activity for 60 days; the external timer keeps working regardless.

### Optional settings (Settings → Secrets and variables → Actions)

| Name | Type | What it does |
|---|---|---|
| `SITE_URL` | Variable | Your site's address, e.g. `https://you.github.io/threat-recap/`. Enables the sitemap, absolute share previews and links in the digest. |
| `NVD_API_KEY` | Secret | Free key from [NVD](https://nvd.nist.gov/developers/request-an-api-key). Makes CVE fetching faster and more reliable. |
| `ANTHROPIC_API_KEY` | Secret | Turns on one-line AI "why it matters" notes for up to 30 widely covered stories per run. That's roughly a few cents a day; leave it unset to stay completely free. |
| `GOATCOUNTER` | Variable | Your [GoatCounter](https://www.goatcounter.com) code for privacy-friendly visitor counts (no cookies). |
| `HIDE_SECTIONS` | Variable | Sections left off the public site, comma-separated. Default `plugins,wall`: the Tenable plugins tab and the wall display (`wall.html`, a dashboard for a screen that stays on). Set it to `plugins` to publish the wall display, or to `none` to show everything. Local copies always show everything. |
| `BUTTONDOWN_USER` | Variable | Your [Buttondown](https://buttondown.com) username. Shows the optional email signup box and turns on the `email-digest` workflow: a weekly digest every Wednesday and a monthly recap on the 1st (everyone who subscribes gets both). |
| `BUTTONDOWN_API_KEY` | Secret | Buttondown API key, used to create the emails. |
| `DIGEST_AUTOSEND` | Variable | `true` sends the emails automatically. Otherwise each one is saved as a draft in Buttondown for you to review and send. |

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
                   digest.js ─► public/digest.html (this week), public/monthly.html (last month)
public/index.html + app.js read those files; no server code or database.
```

`cache/` keeps 30 days of history, CVE scores, PoC lookups, IOCs and AI notes between runs (GitHub Actions stores it with `actions/cache`).
