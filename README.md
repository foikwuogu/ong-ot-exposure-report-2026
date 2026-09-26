# State of OT Vulnerability Exposure in US Oil and Natural Gas, 2026

**Status:** v1.0.0, 2026 edition, published on Zenodo 2026-09-26 (author-verified; see docs/VERIFY_CHECKLIST.md) | **DOI (v1.0.0):** [10.5281/zenodo.22974795](https://doi.org/10.5281/zenodo.22974795) · **All versions:** [10.5281/zenodo.22974794](https://doi.org/10.5281/zenodo.22974794) | **Companion:** PQC baseline, 10.5281/zenodo.22975133 | **Next edition:** December 2027

An annual, reproducible measurement of operational-technology (OT) vulnerability exposure disclosed in CISA ICS advisories that are relevant to the US oil and natural gas (ONG) sector. The report covers volume, vendor concentration, severity, exploitation evidence (CISA KEV, CISA SSVC, FIRST EPSS), weakness classes and remediation signal. Each edition is rebuilt from a frozen, DOI-registered snapshot with a fixed configuration, so editions compare year over year.

**Authors:** Friday Ogochukwu Ikwuogu ([ORCID 0009-0009-2222-1318](https://orcid.org/0009-0009-2222-1318)), Independent Researcher, Odessa, Texas, USA (corresponding); Abidemi Orimogunje (Redeemer's University); Eria Othieno Pinyi (University of Fairfax); David Mike-Ewewie (University of Texas Permian Basin). Roles are in `AUTHORS.json`.

## What is here

```
report/ONG_OT_Exposure_Report_2026.docx/.pdf         the report (final, v1.0.0)
report/stats.json                                    every number the report quotes
report/figures/  report/tables/                      figures 1-6, tables t1-t5
config/scope.json                                    every analytic judgment: de-dup, scope, windows, tiers, thresholds
config/kev_component_attribution.csv                 manual attribution of KEV CVEs to embedded components
code/01_ingest.py ... 05_report.js                   the pipeline, in run order
data/processed/qa_report.txt                         row counts, checks, spot checks - read this first
docs/                                                BUILD_SPEC, CODEBOOK, LIMITATIONS, VERIFY_CHECKLIST, NEXT_STEPS, PUBLISH_GUIDE
```

## Reproduce

Requirements: Python 3.10+ (`pip install -r requirements.txt`), Node 18+ (`npm install`), LibreOffice optional for the PDF.

```
python code/01_ingest.py            # downloads ONG-OT dataset v1.1 from Zenodo (or: --from path/to/ong_ot_dataset_v1.1.csv)
./run_all.sh                        # build, stats + QA, figures, report (watermarked working copy)
./run_all.sh --final                # clean release build (used for v1.0.0)
```

## Sources

Single frozen input: **ONG-OT Vulnerability Prioritization Dataset v1.1** (https://doi.org/10.5281/zenodo.22729882), which joins CISA ICS advisories (via the [ICS Advisory Project](https://github.com/icsadvprj/ICS-Advisory-Project), ODbL v1.0; last advisory 2026-09-10) with CISA KEV, FIRST EPSS, CISA Vulnrichment and MITRE ATT&CK for ICS, all pulled 2026-09-12.

**Important:** v1.1 contains every CVE-advisory pair twice (master file and per-year files both ingested). This pipeline keeps master-file rows only. See docs/LIMITATIONS.md item 3.

## Limitations

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md). The most important: the report measures disclosed exposure, not the installed base; the scope is a proxy; and the 2026 edition covers 1 Jan - 10 Sep.

## License

Code MIT; report, figures and docs CC BY 4.0; derived advisory tables ODbL v1.0 (inherited). See `LICENSE`.

## Citation

See `CITATION.cff`.
