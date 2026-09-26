# Verification checklist (authors complete before any release)

Initial and date each line. `python scripts/publish_gate.py .` checks the mechanical items. The rest are yours.

## Reproduce
- [x] Input SHA-256 b5e3f233...7625 matches PROVENANCE.txt; re-run on the author's own computer 2026-09-26 (compare the file MD5 with the checksum on the Zenodo v1.1 record before release)
- [x] `./run_all.sh` ran clean on the author's computer 2026-09-26; qa_report.txt 7 PASS / 0 FAIL; report/stats.json byte-for-byte identical to the build environment
- [x] Row counts in qa_report.txt agree with the report (the report reads them from stats.json)

## Source-level checks (open each advisory at https://www.cisa.gov/news-events/ics-advisories/<id in lower case>)
- [x] `[KEV in window] ICSA-26-218-01 | CVE-2025-14847 | ABB | ABB Ability Zenon | sev=High | KEV=True | EPSS=0.83218 | tier=1` (confirmed by author 2026-09-26)
- [x] `[KEV in window] ICSA-26-209-04 | CVE-2026-31431 | Siemens | Siemens SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP | sev=Critical | KEV=True | EPSS=0.99907 | tier=1` (confirmed by author 2026-09-26)
- [x] `[highest EPSS] ICSA-26-209-04 | CVE-2026-31431 | Siemens | Siemens SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP | sev=Critical | KEV=True | EPSS=0.99907 | tier=1` (confirmed by author 2026-09-26)
- [x] `[mega advisory] ICSA-26-209-04 | CVE-2021-41617 | Siemens | Siemens SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP | sev=Critical | KEV=False | EPSS=0.02545 | tier=3` (confirmed by author 2026-09-26)
- [x] `[ONG product line] ICSA-26-211-03 | CVE-2026-12562 | Toptech Systems | Toptech Systems RCU II+ and Multiload II+ | sev=High | KEV=False | EPSS=0.00278 | tier=4` (confirmed by author 2026-09-26)
- [x] `[random (seed 2026)] ICSA-26-134-10 | CVE-2025-39756 | Siemens | Siemens SIMATIC | sev=Critical | KEV=False | EPSS=0.00177 | tier=3` (confirmed by author 2026-09-26)
- [x] `[random (seed 2026)] ICSA-26-202-06 | CVE-2005-2096 | Siemens | Siemens CADRA | sev=Critical | KEV=False | EPSS=0.05627 | tier=3` (confirmed by author 2026-09-26)
- [x] `[random (seed 2026)] ICSA-26-209-04 | CVE-2025-40300 | Siemens | Siemens SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP | sev=Critical | KEV=False | EPSS=0.00344 | tier=3` (confirmed by author 2026-09-26)
- [x] `[random (seed 2026)] ICSA-26-027-02 | CVE-2015-2301 | Festo Didactic SE | Festo Didactic SE MES PC | sev=Critical | KEV=False | EPSS=0.1467 | tier=2` (confirmed by author 2026-09-26)
- [x] `[random (seed 2026)] ICSA-26-225-05 | CVE-2026-65309 | ANDRITZ | ANDRITZ HIPASE-250 and 250 SCALA | sev=High | KEV=False | EPSS=0.00152 | tier=4` (confirmed by author 2026-09-26)

## KEV component attributions (report Key findings, Section 3.3, Table 2)
- [x] CVE-2025-14847 (ICSA-26-218-01): MongoDB Server (out-of-bounds read / memory disclosure), confirmed by author against NVD 2026-09-26
- [x] CVE-2026-31431 (ICSA-26-209-04): Linux kernel crypto API (algif_aead), confirmed by author 2026-09-26
- [x] CVE-2025-10585 (ICSA-26-202-06): Google Chromium V8 engine (type confusion), confirmed by author against NVD 2026-09-26
- [x] CVE-2025-13223 (ICSA-26-202-06): Google Chromium V8 engine (type confusion), confirmed by author against NVD 2026-09-26
- [x] CVE-2026-24858 (ICSA-26-071-02): Fortinet FortiOS (RUGGEDCOM APE1808 hosts a Fortinet NGFW), confirmed by author against NVD 2026-09-26
- [x] CVE-2025-32433 (ICSA-26-043-06): Erlang/OTP SSH server (unauthenticated RCE), confirmed by author against NVD 2026-09-26
- [x] CVE-2019-11043 (ICSA-26-027-02): PHP-FPM (env_path_info underflow RCE), confirmed by author against NVD 2026-09-26

## Judgment calls to own (config/scope.json): accept or change, then re-run
- [x] De-duplication: keep ICS Advisory Project master-file rows only (confirmed by author 2026-09-26)
- [x] ONG scope = CISA Energy or "oil and gas" tag OR v1.1 ONG product class (confirmed by author 2026-09-26)
- [x] US relevance regex (includes "Multiple" / "Multiple Countries") (confirmed by author 2026-09-26)
- [x] EV-charging exclusion pattern (16 advisories) (confirmed by author 2026-09-26)
- [x] Window 1 Jan - 10 Sep, or re-run for full year in December (confirmed by author 2026-09-26)
- [x] Priority tiers: KEV; SSVC active/poc or EPSS percentile >= 0.95; Critical; other (confirmed by author 2026-09-26)
- [x] Roll-up ("mega") advisory threshold: > 50 CVEs (confirmed by author 2026-09-26)
- [x] EPSS "high" threshold 0.1 (confirmed by author 2026-09-26)

## Authors and roles
- [x] AUTHORS.json: co-author list and order are right for this project (standard co-authors were used; the ONG-OT dataset used a different set) (confirmed by author 2026-09-26)
- [x] Each co-author has confirmed their CRediT role and added an ORCID if they have one (confirmed by author 2026-09-26)

## Prose
- [x] Report text rewritten or approved in your own voice; every claim defensible; Sections 3.6 (INCONTROLLER) and 4 (implications) re-read with particular care (confirmed by author 2026-09-26)
- [x] References checked; URLs resolve (confirmed by author 2026-09-26)

## Release
- [x] DOI reserved on Zenodo: 10.5281/zenodo.22974795, pasted into report/report_meta.json (2026-09-26); release_date still to set at release
- [x] `./run_all.sh --final` built v1.0.0 on the author's computer 2026-09-26; publish gate clear
- [x] Evidence log row written in docs/EVIDENCE_LOG.csv the day of release (2026-09-26)
