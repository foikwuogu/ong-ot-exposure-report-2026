# Build spec: State of OT Vulnerability Exposure in US Oil and Natural Gas, 2026

```
PROJECT:        State of OT Vulnerability Exposure in US Oil and Natural Gas, 2026. Archetype: annual state-of-the-field report (5) + technical report (9).
QUESTION:       How much OT vulnerability exposure relevant to US oil and natural gas did the public advisory record disclose in 2026,
                where did it concentrate, and how much of it shows evidence of exploitation, measured the same way every year?
SOURCES:        ONG-OT Vulnerability Prioritization Dataset v1.1, doi:10.5281/zenodo.22729882 (CC BY 4.0 / ODbL), itself a join of
                  - CISA ICS advisories via ICS Advisory Project mirror, github.com/icsadvprj/ICS-Advisory-Project (ODbL v1.0), files dated 2026-09-10
                  - CISA KEV catalog, EPSS (FIRST / empiricalsecurity.com), CISA Vulnrichment, MITRE ATT&CK for ICS, all pulled 2026-09-12
                Frozen input; SHA-256 in data/raw/PROVENANCE.txt.
UNIT:           CISA advisory (severity, CVSS, CWE); unique CVE (KEV, EPSS, SSVC, remediation text, priority tier).
MEASURES:       advisory and unique-CVE counts, with and without roll-up advisories (>50 CVEs); vendor count, top-10, HHI;
                CISA severity mix; KEV count/share; EPSS >= 0.10 share; SSVC exploitation; exploitation-first tiers 1-4;
                top-10 CWE vs 2012-2025 share; remediation-text coverage; ONG product-class mix; ATT&CK for ICS overlap; CPG 2.0 mapping.
WINDOWS:        1 Jan - 10 Sep each year (snapshot cutoff 2026-09-10); full years 2012-2025.
SCOPE:          config/scope.json: CISA sector Energy / oil and gas OR ONG product class; US/worldwide distribution; EV charging excluded.
OUTPUTS:        report/ONG_OT_Exposure_Report_2026.docx + .pdf; report/figures/fig1-6; report/tables/t1-t5; report/stats.json;
                data/processed/{cve_advisory_pairs,advisories}.csv; data/processed/qa_report.txt
VENUES:         1. GitHub release v0.1.0 (foikwuogu/ong-ot-exposure-report-2026)  2. Zenodo, upload type "publication / report",
                versioned annually under one concept DOI (2027 edition: Dec 2027)  3. optional arXiv cs.CR summary preprint.
VERIFY POINTS:  de-dup rule; scope rule incl. EV exclusion and US-distribution regex; tier thresholds; mega-advisory threshold;
                KEV component attributions; 10 named spot checks; every sentence of the prose in the authors' own voice.
LICENSE:        code MIT; report and figures CC BY 4.0; derived advisory tables ODbL v1.0.
ASSUMPTIONS:    (1) the edition covers 1 Jan - 10 Sep 2026 until a December re-run on a fresh snapshot; (2) the v1.1 double-ingestion
                is corrected here by keeping master-file rows only; (3) author list = standard author block + standard co-authors.
```
