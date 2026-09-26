# Next steps

## Before the December 2026 release
- Re-pull all five sources (ICS Advisory Project, KEV, EPSS, Vulnrichment, ATT&CK for ICS) with the ONG-OT pipeline, **after fixing its double-ingestion** (read either the master file or the per-year files, not both), and publish that as ONG-OT dataset v1.2 on Zenodo, versioned under concept DOI 10.5281/zenodo.22503185.
- Point code/01_ingest.py at v1.2, set config/scope.json `snapshot_cutoff` and `ytd_end_month_day` to the new last release date (ideally 12-31 for a full-year edition), re-run ./run_all.sh, and re-verify.
- Attribute the remaining KEV CVE and confirm all attributions.

## 2027 edition (Dec 2027)
- Same config, new snapshot; release as a new version under this report's concept DOI; add a year-over-year diff section generated from both stats files.
- Add per-CVE CVSS from NVD or CVE records, removing the advisory-level CVSS limitation.
- Join CISA CSAF remediation fields so fix availability is measured rather than inferred.
- Add time-to-KEV (KEV dateAdded minus advisory date) once KEV dates are in the input.
