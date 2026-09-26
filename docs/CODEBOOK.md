# Codebook

## data/processed/cve_advisory_pairs.csv (one row per unique CVE-advisory pair, all advisories)

| Column | Definition |
|---|---|
| ICS-CERT_Number, cve_id, Vendor, Product, CVSS_Severity, Cumulative_CVSS, CWE_Number, Critical_Infrastructure_Sector, Product_Distribution, Company_Headquarters | As published by CISA, via the ICS Advisory Project mirror, unchanged from the v1.1 input. CVSS, severity and CWE are advisory-level. |
| release_date, release_year | Parsed from Original_Release_Date (MM/DD/YYYY). The report uses this date, not the source `Year` column (they differ for 22 pairs). |
| in_ytd_window | Release month-day falls between config windows.ytd_start_month_day and ytd_end_month_day (01-01 to 09-10). |
| advisory_type | ICSA (industrial) or ICSMA (medical), from the advisory ID prefix. |
| known_exploited, epss, percentile | From v1.1: CISA KEV membership; FIRST EPSS probability and percentile, as of 2026-09-12. |
| ssvc_exploitation | CISA Vulnrichment SSVC "Exploitation" value (none / poc / active), blank if CISA has not scored the CVE. |
| vulnrichment_remediation_text_present, no_patch_available, no_patch_basis | From v1.1 (see its CODEBOOK). |
| ong_product_class, cpg2_applicable_controls, attack_ics_matched_entity | From v1.1. |
| scope_sector_energy / scope_ong_class / scope_us_distribution / scope_excluded_non_ong | Advisory-level scope tests (any row of the advisory qualifies), from config/scope.json. |
| in_scope | (sector OR class) AND US distribution AND NOT excluded. |
| mega_advisory | The advisory lists more than config mega_advisory_cve_threshold (50) CVEs. |
| priority_tier | 1 KEV; 2 SSVC active/poc or EPSS percentile >= 0.95; 3 advisory Critical; 4 other. |

## data/processed/advisories.csv (one row per advisory)

release_date, release_year, in_ytd_window, advisory_type, vendor, title, cvss_severity, cumulative_cvss, n_cves (unique CVEs), any_kev, max_epss, cwes (semicolon list), n_cwes, sector, hq_country, in_scope, scope_* flags, mega_advisory.

## report/tables

- t1_trend_by_year.csv: per-year counts (full year and window), severity shares, KEV share, vendors.
- t2_top_vendors_ytd.csv: top-10 vendors, 2026 window.
- t3_top_cwes_ytd.csv: top-10 CWEs by advisories citing them, 2026 window, with 2012-2025 share.
- t4_priority_tiers.csv: tier counts and shares, both windows and all-time.
- t5_kev_cves_ytd.csv: KEV CVEs in the 2026 window, with component attribution from config/kev_component_attribution.csv.

## report/stats.json

Every number in the report. Top-level blocks: build (row counts), ytd_current, ytd_prior, full_prior_year, all_in_scope (same fields, see `block()` in code/03_stats_qa.py), yoy, universe_ytd_current, trend, trend_summary, vendors_ytd, vendor_concentration, cwes_ytd, cwe_306, kev_ytd_list, kev_ytd_attribution, kev_ytd_table.
