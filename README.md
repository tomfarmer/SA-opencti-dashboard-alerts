# OpenCTI Threat Match Dashboard

A Splunk app that enriches your network telemetry with OpenCTI indicators of compromise (IOCs), writes normalized summary events to `index=opencti_alerts`, and provides analyst‑friendly dashboards to triage, label, and revisit matches.

## About This App
- Purpose: correlate OpenCTI IOCs with DNS, IP/flow, URL/HTTP, and file events; summarize matches; and accelerate analyst review.
- Scope: includes scheduled matchers, backfills, KV lookups, workflow actions, and dashboards (Analyst and Health).

## How The App Works
- Data flow
  - OpenCTI → Splunk: an OpenCTI “Live Stream”/connector populates an upstream lookup (e.g., `opencti_lookup`).
  - This app refreshes purpose‑built KV stores from that lookup:
    - Domains: `opencti_domains_kv` via transform `opencti_lookup_domain` (match_type=WILDCARD(domain))
    - IP/CIDR: `opencti_ips_kv` via transform `opencti_lookup_ip` (match_type=CIDR(ip))
  - Scheduled matchers read telemetry via macros and enrich with those KV stores:
    - DNS: macro `dns_event_sources` (e.g., Zeek DNS)
    - IP: macro `ip_event_sources` + `m_extract_ip_candidates`
- Matches are summarized and written to `index=opencti_alerts` (macro `opencti_alerts_index`) by `collect`.

Summary index model (important)
- `opencti_alerts` is a summary index. We do not write one summary event per raw hit.
- Each matcher aggregates raw events (stats … BY indicator) and writes a single summary row per run window that carries:
  - `hits` (count of raw events), `first_seen` (earliest raw _time), `last_seen` (latest raw _time).
  - `_time` is set to `last_seen` so time pickers reflect recency by last seen.
- This keeps the summary small and dashboards fast. If you truly need one summary event per raw hit, the pipeline can be changed, but it’s rarely desirable.

- Fields written to `index=opencti_alerts`
  - From OpenCTI KV lookups (`opencti_lookup_domain` / `opencti_lookup_ip`):
    - `ioc` (original IOC name/value)
    - `score`
    - `labels`
    - `created_by`
    - `confidence`
  - From telemetry/aggregation in this app:
    - Common: `hits`, `first_seen`, `last_seen`, `src_index`, `src_sourcetype`, `kind`, `_time` (set to `last_seen`), `alert_summary`
    - DNS matches: `match_value` (domain), `matched_field` (query/answer)
    - IP matches: `ip`, `role` (src/dest/unknown)

- Saved searches (matchers & backfills)
  - Near‑real‑time (5 min):
    - `30_dns_match_opencti` (aggregates unique domains before lookup for efficiency)
    - `31_ip_match_opencti`
    - `32_dns_answer_ip_match_opencti`
    - `35_email_match_opencti` (aggregate → lookup → filter for emails; per‑combo write)
  - Backfills (ad‑hoc or scheduled off):
    - `90_backfill_dns_match_opencti`
    - `91_backfill_ip_match_opencti`
    - `92_backfill_dns_answer_ip_match_opencti`

- Handling IOC drift over time
  - Backfills re‑scan historical telemetry against the current IOC sets, capturing matches for indicators added or changed after events were first ingested.
  - Summary `_time` is set to `last_seen` so dashboards reflect the true event chronology; to validate fresh writes, search by `_indextime`.

- “Seen again” logic on the Analyst dashboard
  - The dashboard looks up analyst decisions from `opencti_seenbefore_kv` (via `opencti_seenbefore_kv` lookup), then evaluates `seen_again` as Yes/No based on whether a new `last_seen` is later than `decided_at`.
  - Workflow actions let analysts set `ioc_rating` (malicious/benign/unreviewed), `decided_at`, `decided_by`, and `note` by writing/upserting into `opencti_seenbefore_kv`.

### Per‑combo grouping + multi‑source provenance (Created By)
- Group‑by keys (what defines a single row):
  - Emails: `email + ioc + score + role`
  - Domains: `domain + ioc + score`
  - URLs: `url_candidate + ioc + score`
  - IPs: `ip + ioc + score`
  - Files: `hash + ioc + score`
- Provenance display: we keep one row per combo and collect all producers with `values(created_by)`, then render as a comma‑separated string via `mvjoin(created_by, ", ")`.
- Result: analysts see a compact list with all sources that asserted the IOC for that combo within the time window. If you prefer one row per producer, add `created_by` to the group‑by list instead.

## How To Use
- Dashboards
  - Analyst OpenCTI Threat Match Overview (`default/data/ui/views/opencti_overview.xml`)
    - Summary tiles for flagged Files/Domains/URLs/IPs.
    - “Domain Matches” and “IP Matches” tables with columns: Rating, Indicator, Score, Times Seen, Tags, Created By, Confidence, First/Last Time Seen, Index.
    - Click a row to populate action buttons (set IOC rating), show the source index, and open a ±5s raw‑event drilldown.
    - “Rolling … Matches” tables show today’s matches; use the column picker to show `created_by`/`confidence` if hidden.
  - OpenCTI Threat Match Health (`default/data/ui/views/opencti_health.xml`)
    - KV inventory, scheduler status, and summary‑event counts over time.

- Marking indicators (workflow actions)
  - On the Analyst dashboard row click, use buttons to mark Malicious/Benign/Clear. Actions write to `opencti_seenbefore_kv`; decisions immediately influence Rating and “Seen again”.

- Running backfills
  - Use the saved searches: `90_…`, `91_…`, `92_…` with your desired timepicker.
  - For ad‑hoc single‑line variants, see comments above each saved search in `default/savedsearches.conf`.
  - If you need immediate visibility in “Last 15 minutes” searches, either widen the time window or search by `_indextime` (backfills set `_time=last_seen`).

## Configuration & Customization
- Macros you can tune
  - `opencti_alerts_index`: target summary index (default: `opencti_alerts`)
  - `dns_event_sources`, `ip_event_sources`, `url_event_sources`, `files_event_sources`: define your source indexes.
  - `m_extract_ip_candidates`: list of candidate fields for IP extraction.

- Lookups & transforms
  - `opencti_lookup_domain` → `opencti_domains_kv` (WILDCARD(domain)) includes: domain, name, score, labels, created_by, confidence.
  - `opencti_lookup_ip` → `opencti_ips_kv` (CIDR(ip)) includes: ip, name, score, labels, created_by, confidence.
  - Analyst decisions: `opencti_seenbefore_kv` (fields: _key, indicator, type, ioc_rating, decided_at, decided_by, note).

- Wildcards and matching
  - Domains
    - We normalize to lowercase and strip any trailing dot, then store two patterns for each IOC: `domain.com` and `*.domain.com`.
    - The transform `opencti_lookup_domain` uses `match_type=WILDCARD(domain)`, so it matches the apex and any subdomain (for example `a.b.domain.com`).
  - URLs
    - We strip `http(s)://`, lowercase, and store the host/path in `opencti_urls_kv`. The transform `opencti_lookup_url` uses `match_type=WILDCARD(url)`.
    - This allows patterns like `example.com/*` and `*.example.com/*` to match across path segments and subdomains. Extraction builds candidates as `host.uri` or `host.uri_path` when available.
  - IPs
    - We use network-aware matching via `match_type=CIDR(ip)` so `10.0.0.0/8` matches `10.1.2.3` (both IPv4 and IPv6 supported).
  - Why we do it this way
    - Correctness: Wildcards avoid blind spots (e.g., subdomains) without enumerating all permutations; CIDR matches ranges as intended.
    - Performance: We pre-aggregate unique candidates (domain/url) before looking them up to cut KV scans by orders of magnitude.
    - Predictability: Normalization (lowercasing, scheme/trailing dot removal) makes the matching behavior deterministic across sources.

- Packaging
  - App label: “OpenCTI Threat Match Dashboard”; dashboard title: “Analyst OpenCTI Threat Match Overview”.
  - App icon/logo: place `appserver/static/appIcon.png` (48×48) and `appserver/static/appLogo.png` (≈72×72). Optional dark variants: `appIconAlt.png`, `appLogoAlt.png`.
  - Build script: `scripts/build.sh` produces a tarball that unpacks as `SA-opencti-threat-match-dashboard`.

## Notes & Tips
- Efficiency: The DNS matcher aggregates unique domains before wildcard lookups to reduce KV operations.
- Time semantics: Dashboards use `_time` (set to `last_seen`), while ingestion monitoring is easier with `_indextime`.
- Troubleshooting
  - If matchers run but dashboards show blanks for Created By/Confidence, ensure the refreshers have populated those fields into the KV stores and that the saved searches include them before `collect`.
  - Verify macros resolve as expected: `| makeresults | eval idx="`opencti_alerts_index`" | table idx`.

---
If you need additional data sources, fields, or dashboards, extend the macros and saved searches and the dashboards will follow.
