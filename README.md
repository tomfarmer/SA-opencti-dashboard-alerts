# OpenCTI Threat Match Dashboard

A Splunk app that enriches your network telemetry with OpenCTI indicators of compromise (IOCs), writes normalized summary events to `index=opencti_alerts`, and provides analyst‑friendly dashboards to triage, label, and revisit matches.

## About This App
- Purpose: correlate OpenCTI IOCs with DNS, IP/flow, URL/HTTP, and file events; summarize matches; and accelerate analyst review.
- Scope: includes scheduled matchers, backfills, KV lookups, workflow actions, and dashboards (Analyst and Health).

## How The App Works
- Data flow
  - OpenCTI → Splunk: an OpenCTI “Live Stream”/connector populates an upstream lookup (e.g., `opencti_lookup`).
  - This app refreshes two families of KV stores from that lookup:
    1) IOC match KVs (used for matching; populated by refresh_opencti_* searches)
       - Domains: `opencti_domains_kv` via transform `opencti_lookup_domain` (match_type=WILDCARD(domain))
       - IP/CIDR: `opencti_ips_kv` via transform `opencti_lookup_ip` (match_type=CIDR(ip))
       - URLs: `opencti_urls_kv` via transform `opencti_lookup_url` (match_type=WILDCARD(url))
       - File hashes: `opencti_hashes_kv` via transform `opencti_lookup_hash`
       - Emails: `opencti_emails_kv` via transform `opencti_lookup_email`
    2) Threat‑feed union KVs (used for provenance/enrichment at read‑time; populated by refresh_threatfeed_current_* searches)
       - Domains: `threatfeed_current_domain_kv` via transform `opencti_threatfeed_current_domain`
       - IPs: `threatfeed_current_ip_kv` via transform `opencti_threatfeed_current_ip`
       - URLs: `threatfeed_current_url_kv` via transform `opencti_threatfeed_current_url`
       - File hashes: `threatfeed_current_hash_kv` via transform `opencti_threatfeed_current_hash`
       - Emails: `threatfeed_current_email_kv` via transform `opencti_threatfeed_current_email`
       - Schema per row: `ioc`, `threat_feed_current` (MV of producers), `feed_scores` (MV of `feed:score` pairs), `max_score`, `min_score`, `score_range` (e.g., `50–90`).
  - Scheduled matchers read telemetry via macros and enrich with the IOC match KVs only (fast, deterministic matching), then dashboards optionally enrich with the union KVs to show “Threat Feed Current”.
    - Domains: macro `domains_event_sources` (e.g., Zeek DNS)
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
    - `domains_match_opencti` (aggregates unique domains before lookup for efficiency)
    - `ip_match_opencti`
    - `dns_answer_ip_match_opencti`
    - `email_match_opencti` (aggregate → lookup → filter for emails; per‑combo write)
  - Backfills (ad‑hoc or scheduled off):
    - `backfill_domains_match_opencti`
    - `backfill_ip_match_opencti`
    - `backfill_domains_answer_ip_match_opencti`

### Public‑only IP matching (dropping private space)
- IP candidate extraction (`m_extract_ip_candidates` in `default/macros.conf`) now:
  - Builds a unified `ip` field from common src/dest fields.
  - Keeps only syntactically valid IPv4/IPv6 addresses.
  - Explicitly drops private and non‑routable ranges:
    - IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`.
    - IPv6: `::1/128`, `fc00::/7` (ULA), `fe80::/10` (link‑local).
- The DNS answers→IP matchers (NRT and backfill) use the same predicate before `m_opencti_lookup_ip(ip)`.
- Result: OpenCTI IP lookups and alerts are restricted to public/external IPs; purely internal/private traffic is ignored by the threat‑matchers.

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

### Two Writers? No — clean split
- IOC match KVs (refresh_opencti_*) populate `opencti_*` KV stores. These are used for matching and continue to be the only writers of those stores.
- Threat‑feed union KVs (refresh_threatfeed_current_*) populate the separate `threatfeed_current_*` KV stores. These are used for dashboard enrichment only.
- There is no overlap: you do NOT have two writers for the same IOC KV.

### Why split is efficient
- Matching stays fast: matchers touch a single, type‑specific KV optimized for `WILDCARD(domain)`/`CIDR(ip)` semantics and write compact summary rows.
- Provenance is computed once per refresh window (hourly) from `opencti_lookup`, not per match execution. Dashboards do a single exact lookup by `ioc` to show “Threat Feed Current”, `max_score`, and `score_range`.
- Operationally resilient: you can refresh union KVs at a different cadence without impacting matcher latency or correctness.
- Easy to test/roll back: IOC matching and provenance enrichment are independently deployable.

### Store‑time vs Match‑time Semantics (important)
- We set `threat_feed_at_match_time=created_by` immediately after the IOC lookup inside each matcher/backfill. If `created_by` is missing in the IOC KV, that assignment yields null and the dashboard’s “Threat Feed At Match Time” column will be empty — you lose producer context in the summary event.
- Field meanings (keep them separate):
  - `created_by` (in IOC KVs): which producer asserted this IOC in the feed materialized into the match KV (store‑time context).
  - `threat_feed_at_match_time` (in summaries): which producer(s) were recorded when the matcher ran for that row (match‑time context).
  - `threat_feed_current` (in union KVs): which producers assert the IOC now — a union across feeds built from `opencti_lookup` by the refresh_threatfeed_current_* searches (current truth).
- Why separate: this lets dashboards show both historical provenance (“at match time”) and current truth (union), without conflating them.

### Threat‑Feed Current: per‑feed scores (feed_scores)
- Each union lookup (`opencti_threatfeed_current_[domain|ip|url|hash|email]`) exposes `feed_scores`, a multivalue field of strings like `AlienVault:75`, `VendorX:90` for the IOC.
- How the dashboard uses it
- “Low Score” column shows the lowest producer score (min) for the IOC in the time window.
- “Max Score” shows the highest producer score; companion columns “Low Score By” / “Max Score By” show the producer names. Numeric columns remain numeric for proper sorting.
- How to use in your own searches
  - Show per‑feed scores for one IOC:
    - `| eval ioc="example.com" | lookup opencti_threatfeed_current_domain ioc OUTPUT feed_scores | mvexpand feed_scores | eval feed=mvindex(split(feed_scores,":"),0), feed_score=tonumber(mvindex(split(feed_scores,":"),1)) | table feed feed_score`
  - Filter alerts where a specific producer’s score ≥ 80:
    - `index=opencti_alerts earliest=-24h | lookup opencti_threatfeed_current_domain ioc OUTPUT feed_scores | mvexpand feed_scores | eval feed=mvindex(split(feed_scores,":"),0), feed_score=tonumber(mvindex(split(feed_scores,":"),1)) | search feed="VendorX" feed_score>=80`
  - Get which producer set the max/min for each IOC:
    - `... | mvexpand feed_scores | eval f=mvindex(split(feed_scores,":"),0), s=tonumber(mvindex(split(feed_scores,":"),1)) | eventstats max(s) as mx min(s) as mn by ioc | eval max_by=if(s=mx,f,null()), min_by=if(s=mn,f,null()) | stats values(max_by) as max_score_by values(min_by) as min_score_by by ioc`

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
  - `opencti_lookup_domain` → `opencti_domains_kv` (WILDCARD(domain)) includes: domain, score, labels, created_by, confidence.
  - `opencti_lookup_ip` → `opencti_ips_kv` (CIDR(ip)) includes: ip, score, labels, created_by, confidence.
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

### Refresh For Testing

Use this sequence to reset and repopulate all KVs so you can test changes deterministically.

1) Clear the IOC match KVs (domains, IPs, URLs, hashes, emails)
   - Domains: `| inputlookup opencti_lookup_domain | head 0 | outputlookup opencti_lookup_domain`
   - IPs: `| inputlookup opencti_lookup_ip | head 0 | outputlookup opencti_lookup_ip`
   - URLs: `| inputlookup opencti_lookup_url | head 0 | outputlookup opencti_lookup_url`
   - Hashes: `| inputlookup opencti_lookup_hash | head 0 | outputlookup opencti_lookup_hash`
   - Emails: `| inputlookup opencti_lookup_email | head 0 | outputlookup opencti_lookup_email`
   - Notes: these commands overwrite the collection with an empty set (no append), effectively clearing it.

2) Repopulate IOC match KVs from the master lookup
   - `| savedsearch SA-opencti-dashboard-alerts:refresh_opencti_domains_kv`
   - `| savedsearch SA-opencti-dashboard-alerts:refresh_opencti_ips_kv`
   - `| savedsearch SA-opencti-dashboard-alerts:refresh_opencti_urls_kv`
   - `| savedsearch SA-opencti-dashboard-alerts:refresh_opencti_hashes_kv`
   - `| savedsearch SA-opencti-dashboard-alerts:refresh_opencti_emails_kv`
   - Tip: ensure `opencti_lookup` has content before running these.

3) Clear the Threat‑Feed Current union KVs (optional)
   - Domains: `| inputlookup opencti_threatfeed_current_domain | head 0 | outputlookup opencti_threatfeed_current_domain`
   - IPs: `| inputlookup opencti_threatfeed_current_ip | head 0 | outputlookup opencti_threatfeed_current_ip`
   - URLs: `| inputlookup opencti_threatfeed_current_url | head 0 | outputlookup opencti_threatfeed_current_url`
   - Hashes: `| inputlookup opencti_threatfeed_current_hash | head 0 | outputlookup opencti_threatfeed_current_hash`
   - Emails: `| inputlookup opencti_threatfeed_current_email | head 0 | outputlookup opencti_threatfeed_current_email`

4) Rebuild Threat‑Feed Current union KVs
   - `| savedsearch SA-opencti-dashboard-alerts:refresh_threatfeed_current_domain`
   - `| savedsearch SA-opencti-dashboard-alerts:refresh_threatfeed_current_ip`
   - `| savedsearch SA-opencti-dashboard-alerts:refresh_threatfeed_current_url`
   - `| savedsearch SA-opencti-dashboard-alerts:refresh_threatfeed_current_hash`
   - `| savedsearch SA-opencti-dashboard-alerts:refresh_threatfeed_current_email`

5) Generate fresh summaries (so new `threat_feed_at_match_time` is persisted)
   - `| savedsearch SA-opencti-dashboard-alerts:domains_match_opencti`
   - `| savedsearch SA-opencti-dashboard-alerts:ip_match_opencti`
   - `| savedsearch SA-opencti-dashboard-alerts:url_match_opencti`
   - `| savedsearch SA-opencti-dashboard-alerts:file_hash_match_opencti`
   - `| savedsearch SA-opencti-dashboard-alerts:email_match_opencti`

6) Verify KVs and summaries
   - IOC KVs:
     - Domains: `| inputlookup opencti_lookup_domain | stats count`
     - IPs: `| inputlookup opencti_lookup_ip | stats count`
     - URLs: `| inputlookup opencti_lookup_url | stats count`
     - Hashes: `| inputlookup opencti_lookup_hash | stats count`
     - Emails: `| inputlookup opencti_lookup_email | stats count`
   - Union KVs:
     - Domains: `| inputlookup opencti_threatfeed_current_domain | head 5`
     - … repeat for IP/URL/Hash/Email
   - Summaries (example for email):
     - `index=opencti_alerts sourcetype=opencti:email_match earliest=-15m`
       `| table email threat_feed_at_match_time score role first_seen last_seen`

---
If you need additional data sources, fields, or dashboards, extend the macros and saved searches and the dashboards will follow.

## Late‑Arriving Data (_indextime gating)

Some sources (e.g., Zeek on busy indexers) can have noticeable ingestion delay: events with `_time=10:00` might only get indexed at `10:32`. If a near‑real‑time search only looks at the last 5 minutes of event time, those late arrivals can be missed until a backfill runs.

To solve this, the scheduled matchers now combine a wide event‑time window with a narrow index‑time slice:

- Event time window: `dispatch.earliest_time = -1h@m` and `dispatch.latest_time = now`
- Index time gating (applied right after the source macro):
  `| search _indextime>=relative_time(now(), "-5m@m") _indextime<relative_time(now(), "@m")`

What this does
- Captures late arrivals: even if Zeek indexes an event 30 minutes after it occurred, it is processed when its `_indextime` falls into the current 5‑minute slice. The wider `-1h@m` event‑time window ensures the event’s older `_time` isn’t filtered out.
- Avoids duplicates: each run processes exactly the last 5 minutes of indexing time, aligned to the minute, so overlapping runs don’t double count.
- Keeps summaries correct: we still aggregate by indicator and set `_time=last_seen` from event time so dashboards reflect when the activity actually happened, not when it was indexed.

Tuning for your environment
- If your ingestion delay is occasionally more than 1 hour, increase the event window (e.g., `-2h@m`).
- If your scheduler runs less frequently, widen the index‑time slice to match (e.g., `-10m@m` for 10‑minute cadence).
- Backfills remove the `_indextime` gate and re‑scan any historical range you choose, so use them to recover matches outside your configured event window.

Tip: we centralized this as a macro. In `default/macros.conf` use:
- `m_index_time_gate` for the default 5‑minute slice.
- `m_index_time_gate_window("-10m@m")` if you prefer a different slice without editing every saved search.
