# Publish guide: State of OT Vulnerability Exposure in US Oil and Natural Gas, 2026

No push was automated from the build session: no GitHub or Zenodo token was supplied, and the build environment's network policy blocks both. Everything below is for you to do, in one sitting, **after** docs/VERIFY_CHECKLIST.md is complete.

## 0. Final build
1. On Zenodo, click **New upload**, then **Reserve DOI** (under "Digital Object Identifier"). Copy the DOI; do not publish yet.
2. Paste it into `report/report_meta.json` → `"doi"`; set `"release_date"` (YYYY-MM-DD).
3. `./run_all.sh --final` → produces `report/ONG_OT_Exposure_Report_2026.docx` and `.pdf` without DRAFT stamps.
4. `python scripts/publish_gate.py . --allow-draft-in code/ scripts/ data/raw/ docs/VERIFY_CHECKLIST.md docs/PUBLISH_GUIDE.md` must print a pass (those paths mention DRAFT only because they implement or describe the stamping). Change the README status line to "Released v1.0.0, <date>, DOI <doi>". Delete the `_DRAFT` files from report/.

## 1. GitHub (repository: foikwuogu/ong-ot-exposure-report-2026)
1. github.com/new → name `ong-ot-exposure-report-2026`, public, **no** README/license (the repo has them).
2. In the project folder:
   ```
   git init -b main
   git add -A
   git commit -m "State of OT Vulnerability Exposure in US ONG, 2026 edition v1.0.0"
   git remote add origin https://github.com/foikwuogu/ong-ot-exposure-report-2026.git
   git push -u origin main
   ```
   (Or, with a token: `GITHUB_TOKEN=... python scripts/publish_github.py --repo ong-ot-exposure-report-2026 --tag v1.0.0`.)
3. Releases → Draft a new release → tag `v1.0.0`, title "2026 edition (v1.0.0)", notes: first edition; covers CISA ICS advisories 1 Jan - 10 Sep 2026; input doi:10.5281/zenodo.22729882; see docs/LIMITATIONS.md.

## 2. Zenodo (finish the upload you reserved in step 0)
- **Files**: the final PDF, the final DOCX, and the GitHub release zip.
- **Resource type**: Publication → Report.
- **Title**: State of OT Vulnerability Exposure in US Oil and Natural Gas, 2026
- **Creators** (in order, from AUTHORS.json): Ikwuogu, Friday Ogochukwu (ORCID 0009-0009-2222-1318; Independent Researcher, Odessa, Texas, USA); Orimogunje, Abidemi (Redeemer's University); Pinyi, Eria Othieno (University of Fairfax); Mike-Ewewie, David (University of Texas Permian Basin).
- **Description**: paste from `scripts/zenodo_metadata.json` → description.
- **Version**: 1.0.0 (2026 edition). **License**: CC BY 4.0. **Keywords**: from zenodo_metadata.json.
- **Related identifiers**: `10.5281/zenodo.22729882` *is derived from*; GitHub release URL *is supplemented by*; `10.5281/zenodo.22975133` (PQC baseline) *is supplemented by*.
- Publish. The DOI you reserved goes live.
- API alternative: `ZENODO_SANDBOX_TOKEN=... python scripts/zenodo_deposit.py --files report/ONG_OT_Exposure_Report_2026.pdf report/ONG_OT_Exposure_Report_2026.docx release.zip --metadata scripts/zenodo_metadata.json --sandbox` first, then with `ZENODO_TOKEN` and `--publish`.

## 3. Annual versions (Dec 2027 and after)
On the Zenodo record: **New version**. Each edition gets its own DOI; the concept DOI always resolves to the latest. Paste the concept DOI into report_meta.json `concept_doi` after the first release.

## 4. Optional: arXiv (cs.CR) summary preprint
Scope fits cs.CR. First-time submitters in cs.CR may need endorsement (arxiv.org/auth/endorse); ask a co-author who has published there. Upload the final PDF, authors exactly as in AUTHORS.json, license CC BY 4.0, comments: "Annual report; data and code at <GitHub URL>; DOI <Zenodo DOI>".

## 5. The same day
Add a row to docs/EVIDENCE_LOG.csv (date, artifact, type, venue, DOI, status, files saved). Save a PDF of the Zenodo record page. Update README status line and CITATION.cff `doi`.
