# Limitations

Numbered for reference from the report and the verification checklist. Written before the discussion section.

1. **Disclosed, not deployed.** Counts measure what vendors and CISA disclose. They do not measure the installed base in US ONG facilities, or patch status. Vendors with mature PSIRTs publish more advisories.
2. **Scope is a proxy.** CISA's Energy tag covers electricity as well as oil and natural gas. Some electricity-only products remain in scope, and some ONG-used products tagged only with other sectors and absent from the v1.1 taxonomy are excluded. The EV-charging exclusion is a title/vendor pattern (16 advisories removed).
3. **Input double-ingestion.** The published v1.1 dataset contains every CVE-advisory pair twice (27,944 rows, 13,791 unique pairs), because the ICS Advisory Project master file and its per-year files were both ingested. This report keeps master-file rows only. The QA report shows no pairs lost. Counts cited from v1.1 itself are about double.
4. **Advisory-level severity and CWE.** A roll-up advisory contributes many CWEs, and all of its CVEs share one severity. Figures 2 and 6 and Table 1 report roll-up sensitivity.
5. **Point-in-time enrichment.** KEV, EPSS and SSVC are as of 2026-09-12 for every year, so recent CVEs have had less time to accumulate exploitation evidence and SSVC coverage (2026 SSVC coverage 51.4% vs 2025 87.0%).
6. **Mirror dependency.** Advisory fields come from the ICS Advisory Project transcription, not directly from cisa.gov. The spot checks are the control.
7. **Partial year.** The edition covers 1 Jan - 10 Sep 2026. The December rebuild will change every number.
8. **KEV component attribution** is a manual reading of CVE descriptions (config/kev_component_attribution.csv). All 7 were confirmed by the author against NVD on 2026-09-26.
9. **Remediation signal.** Machine-readable CNA remediation text covers only a minority of CVEs. "No text" is treated as unknown.
10. **The build environment could not reach cisa.gov, first.org or nvd.nist.gov** (egress policy). No source was re-fetched. The report relies entirely on the DOI-registered v1.1 snapshot, and verification against live CISA pages is the author's step.
