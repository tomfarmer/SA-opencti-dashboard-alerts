Place a 48x48 PNG icon named appIcon.png in this folder to brand the app in Splunk Web.

Guidance
- File: appserver/static/appIcon.png
- Size: 48x48 px (PNG, transparent background recommended)
- Optional dark-mode variant (Splunk 9+): appIconAlt.png

After adding the file, reload Splunk Web or restart Splunk to see the new icon.

---
Dashboard notes (per‑combo + Created By)
- Tables show one row per indicator “combo” and then list all producers in the Created By column.
- Group‑by keys per type:
  - Email: email + ioc + score + role
  - Domain: domain + ioc + score
  - URL: url_candidate + ioc + score
  - IP: ip + ioc + score
  - File: hash + ioc + score
- Provenance is summarized with `values(created_by)` and rendered as a comma‑separated string via `mvjoin(created_by, ", ")` so analysts can see all sources at a glance.

---
KV Stores and Writers (important)
- IOC match KVs (used for matching; populated by refresh_opencti_* refreshers)
  - `opencti_domains_kv`, `opencti_ips_kv`, `opencti_urls_kv`, `opencti_hashes_kv`, `opencti_emails_kv`
  - Lookups: `opencti_lookup_domain|ip|url|hash|email`
  - Consumers: all matchers and backfills.
- Threat‑feed union KVs (used for read‑time provenance; populated by refresh_threatfeed_current_* refreshers)
  - `threatfeed_current_domain_kv`, `..._ip_kv`, `..._url_kv`, `..._hash_kv`, `..._email_kv`
  - Lookups: `opencti_threatfeed_current_*`
  - Fields: `ioc`, `threat_feed_current` (MV producers), `max_score`, `min_score`, `score_range`.
  - Consumers: dashboard tables (to show “Threat Feed Current”, “Max Score”, “Score Range”).

No conflict: IOC match KVs and threat‑feed union KVs are separate. You do not have two writers for the same KV.

Why split:
- Keep matchers fast and deterministic (type‑specific KV, wildcard/CIDR semantics).
- Build provenance once per hour from the master lookup, not per match. Dashboards do a single exact lookup by `ioc`.

---
Refresh For Testing (cheat sheet)
- Clear IOC match KVs (overwrites with empty):
  - Domains: `| inputlookup opencti_lookup_domain | head 0 | outputlookup opencti_lookup_domain`
  - IPs: `| inputlookup opencti_lookup_ip | head 0 | outputlookup opencti_lookup_ip`
  - URLs: `| inputlookup opencti_lookup_url | head 0 | outputlookup opencti_lookup_url`
  - Hashes: `| inputlookup opencti_lookup_hash | head 0 | outputlookup opencti_lookup_hash`
  - Emails: `| inputlookup opencti_lookup_email | head 0 | outputlookup opencti_lookup_email`
- Repopulate IOC match KVs:
  - `| savedsearch SA-OpenCTIThreatMatch:refresh_opencti_domains_kv`
  - `| savedsearch SA-OpenCTIThreatMatch:refresh_opencti_ips_kv`
  - `| savedsearch SA-OpenCTIThreatMatch:refresh_opencti_urls_kv`
  - `| savedsearch SA-OpenCTIThreatMatch:refresh_opencti_hashes_kv`
  - `| savedsearch SA-OpenCTIThreatMatch:refresh_opencti_emails_kv`
- Clear Threat‑Feed Current KVs:
  - Domains/IPs/URLs/Hashes/Emails: `| inputlookup opencti_threatfeed_current_<type> | head 0 | outputlookup opencti_threatfeed_current_<type>`
- Rebuild Threat‑Feed Current KVs:
  - `| savedsearch SA-OpenCTIThreatMatch:refresh_threatfeed_current_domain`
  - `| savedsearch SA-OpenCTIThreatMatch:refresh_threatfeed_current_ip`
  - `| savedsearch SA-OpenCTIThreatMatch:refresh_threatfeed_current_url`
  - `| savedsearch SA-OpenCTIThreatMatch:refresh_threatfeed_current_hash`
  - `| savedsearch SA-OpenCTIThreatMatch:refresh_threatfeed_current_email`
- Generate fresh summaries so `threat_feed_at_match_time` persists:
  - `| savedsearch SA-OpenCTIThreatMatch:dns_match_opencti` … `email_match_opencti`

---
Semantics: store‑time vs match‑time
- Matchers set `threat_feed_at_match_time=created_by` right after the IOC lookup. If `created_by` is missing in the IOC KV, `threat_feed_at_match_time` will be null and the “Threat Feed At Match Time” column will be empty.
- Meanings:
  - `created_by` (IOC KVs): producer that asserted the IOC in the KV (store‑time context).
  - `threat_feed_at_match_time` (summaries): producer(s) captured when the matcher wrote the summary (match‑time context).
  - `threat_feed_current` (union KVs): producers that assert the IOC now (from `opencti_lookup`, built by refresh_threatfeed_current_* searches).
- Keeping these separate lets the UI show both history and current truth without conflating them.
