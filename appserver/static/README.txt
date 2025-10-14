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
