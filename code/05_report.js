// Step 5 - build the report (DOCX) from report/stats.json, report/report_meta.json and AUTHORS.json.
//   node code/05_report.js            -> DRAFT-stamped report
//   node code/05_report.js --final    -> clean report (only after the verification gate)
// Every number below is read from stats.json. Do not type numbers into this file.
const fs = require("fs");
const path = require("path");
const L = require("./lib_docx");

const ROOT = path.resolve(__dirname, "..");
const S = JSON.parse(fs.readFileSync(path.join(ROOT, "report", "stats.json"), "utf8"));
const M = JSON.parse(fs.readFileSync(path.join(ROOT, "report", "report_meta.json"), "utf8"));
const A = JSON.parse(fs.readFileSync(path.join(ROOT, "AUTHORS.json"), "utf8"));
const FINAL = process.argv.includes("--final");
const FIGDIR = path.join(ROOT, "report", "figures");
const T = (f) => fs.readFileSync(path.join(ROOT, "report", "tables", f), "utf8").trim().split("\n").map((l) => l.split(","));

const n = (x) => (x === null || x === undefined ? "n/a" : Number(x).toLocaleString("en-US"));
const p = (x) => (x === null || x === undefined ? "n/a" : `${Number(x).toFixed(1)}%`);
const sg = (x) => (x === null || x === undefined ? "n/a" : `${x > 0 ? "+" : ""}${Number(x).toFixed(1)}%`);
const Y = S.edition, Y1 = Y - 1, W = S.ytd_label;
const cu = S.ytd_current, pr = S.ytd_prior, fy = S.full_prior_year, all = S.all_in_scope, yoy = S.yoy;
const B = S.build, SC = B.scope_components_advisories, vc = S.vendor_concentration, ts = S.trend_summary;
const ka = S.kev_ytd_attribution, c306 = S.cwe_306;
const doi = M.doi ? `https://doi.org/${M.doi}` : "[DOI - reserve on Zenodo, paste into report/report_meta.json]";
const people = [...A.authors, ...A.collaborators];

const kids = [];
const add = (...xs) => xs.flat().forEach((x) => kids.push(x));

// ---------------- title page ----------------
add(new L.Paragraph({ spacing: { before: 1400, after: 120 }, children: [new L.TextRun({ text: M.title, bold: true, size: 44, color: "1C5CAB" })] }));
add(new L.Paragraph({ spacing: { after: 360 }, children: [new L.TextRun({ text: `${M.subtitle}. Covers CISA ICS advisories published ${W} ${Y}, with a ${S.trend[0].year}-${Y1} baseline.`, size: 24, color: L.INK2 })] }));
if (!FINAL) add(L.BANNER("DRAFT for author verification. Not for citation or circulation. Every figure, number and judgment call must be checked against docs/VERIFY_CHECKLIST.md before release."));
people.forEach((a, i) => {
  add(new L.Paragraph({ spacing: { after: 20 }, children: [new L.TextRun({ text: a.name + (a.corresponding ? " (corresponding author)" : ""), bold: true, size: 21 })] }));
  add(new L.Paragraph({ spacing: { after: 140 }, children: [new L.TextRun({ text: [a.affiliation, a.orcid ? `ORCID ${a.orcid}` : "", a.email].filter(Boolean).join(" · "), size: 18, color: L.INK2 })] }));
});
add(L.RULEPARA());
add(L.P(`**Version** ${M.version}${FINAL ? "" : " (draft)"} · **Release date** ${M.release_date || "set at release"} · **DOI** ${doi}`));
add(L.P(`**Input snapshot** ${S.input.dataset}, doi:${S.input.doi}; KEV, EPSS and CISA SSVC values as of ${S.input.sources_pulled}; last advisory in the snapshot published ${S.snapshot_cutoff}.`));
add(L.P(`**Series** ${M.series_note}`));
add(L.P(`**License** ${M.license}`));
add(L.P(`**Suggested citation** ${people.map((a) => `${a.family}, ${a.given.split(" ").map((g) => g[0] + ".").join(" ")}`).join(", ")} (${Y}). _${M.title}_. ${M.subtitle}, v${M.version}. Zenodo. ${doi}`));
add(L.PB());

// ---------------- key findings ----------------
add(L.H1("Key findings"));
add(L.P(`All comparisons use the same calendar window (${W}) in each year, so ${Y} is compared like-for-like with ${Y1}. "ONG-relevant" is defined in Section 2.3.`));
add(L.BUL(`**Advisory volume reached a series high.** CISA published ${n(cu.advisories)} ONG-relevant ICS advisories in ${W} ${Y}, ${sg(yoy.advisories)} on the same window of ${Y1} (${n(pr.advisories)}) and the highest of the ${ts.ytd_years_compared} years in the series. ${Y1} as a whole produced ${n(fy.advisories)}.`));
add(L.BUL(`**The CVE count doubled, but almost entirely through roll-ups.** Unique CVEs rose from ${n(pr.unique_cves)} to ${n(cu.unique_cves)} (${sg(yoy.unique_cves)}). Set aside the ${n(cu.mega_advisories)} advisories that each list more than ${S.config.mega_threshold} CVEs, typically bundled third-party components in one firmware image, and growth falls to ${sg(yoy.unique_cves_excl_mega)} (${n(pr.unique_cves_excl_mega)} to ${n(cu.unique_cves_excl_mega)}).`));
add(L.BUL(`**The vendor base widened sharply.** ${n(cu.vendors)} vendors appeared, against ${n(pr.vendors)} in the same window of ${Y1} (${sg(yoy.vendors)}). Concentration roughly halved (Herfindahl-Hirschman index ${n(vc.hhi_ytd_prior)} to ${n(vc.hhi_ytd_current)}), although the top five vendors still account for ${p(vc.top5_share_pct)} of advisories, led by ${vc.top1_vendor} (${p(vc.top1_share_pct)}).`));
add(L.BUL(`**Exploitation evidence remains concentrated in a small set.** ${n(cu.kev_cves)} CVEs (${p(cu.kev_pct)}) are in CISA's Known Exploited Vulnerabilities catalog, the same count as in ${Y1}. Including CISA SSVC exploitation flags and the top 5% of EPSS, ${n(cu.tier12)} CVEs (${p(cu.tier12_pct)}) carry some exploitation evidence, against ${p(pr.tier12_pct)} in ${Y1}.`));
add(L.BUL(`**Known-exploited exposure is inherited, not native.** ${ka.third_party === cu.kev_cves ? `All ${n(cu.kev_cves)} KEV-listed CVEs are` : `Of the ${n(cu.kev_cves)} KEV-listed CVEs, ${n(ka.third_party)} are`} attributed to third-party software embedded in OT products (operating-system kernel, database, browser engine, SSH stack, web runtime, firewall OS)${ka.unknown ? `, ${n(ka.vendor_native)} to vendor-native OT firmware, and ${n(ka.unknown)} is not yet attributed` : `, and ${n(ka.vendor_native)} to vendor-native OT firmware`}.`));
add(L.BUL(`**Missing authentication is the leading weakness.** CWE-306 (missing authentication for a critical function) appears in ${n(c306.ytd_current_advisories)} advisories (${p(c306.ytd_current_pct)}), up from a ${p(c306.hist_pct)} share across ${S.trend[0].year}-${Y1}, and ranks first in ${Y}.`));
add(L.BUL(`**The patch signal is thin.** A vendor remediation statement is machine-readable in the CVE record for only ${p(cu.remediation_text_pct)} of in-scope ${Y} CVEs, so "no patch available" cannot be measured reliably from public data; ${n(cu.no_patch_cves)} CVEs carry an explicit no-fix statement.`));
add(L.PB());

// ---------------- 1 introduction ----------------
add(L.H1("1. Purpose and scope of the series"));
add(L.P(`Operational technology (OT) in the US oil and natural gas (ONG) sector, including controllers, remote terminal units, SCADA servers, flow computers and the engineering software around them, is disclosed through a public vulnerability pipeline: vendor and researcher reports, coordinated by CISA and published as ICS advisories, then enriched by CISA's Known Exploited Vulnerabilities (KEV) catalog, CISA's Vulnrichment decision points and FIRST's Exploit Prediction Scoring System (EPSS). Operators, regulators and researchers each read this pipeline, but the sector has no fixed, reproducible yardstick for how much exposure it discloses in a year, where that exposure concentrates, or how much of it is actually exploited.`));
add(L.P(`This report provides that yardstick. It is designed as an annual series. The measurement definitions (scope, windows, tiers) are fixed in one configuration file and the whole report is regenerated from a frozen, DOI-registered input snapshot, so each edition can be compared with the last and any reader can reproduce every number. ${M.series_note}`));
add(L.P(`The report measures **disclosed** exposure, meaning what the public advisory record says about products used in ONG operations. It does not measure the installed base, how many of these products any operator runs, or whether a given site is patched. Section 5 sets out what that distinction means for interpretation.`));

// ---------------- 2 data and methods ----------------
add(L.H1("2. Data and methods"));
add(L.H2("2.1 Input snapshot"));
add(L.P(`The single input is the ${S.input.dataset} (doi:${S.input.doi}), a published join of (i) CISA ICS advisories as mirrored by the ICS Advisory Project (ODbL v1.0); (ii) the CISA KEV catalog; (iii) FIRST EPSS scores; (iv) CISA Vulnrichment CVE records, including CNA solution and workaround text and CISA's SSVC decision points; and (v) MITRE ATT&CK for ICS group and software profiles. All sources were pulled on ${S.input.sources_pulled}. The file was ingested unchanged and its SHA-256 is recorded in data/raw/PROVENANCE.txt.`));
add(L.H2("2.2 De-duplication"));
add(L.P(`The published v1.1 file contains ${n(B.input_rows)} rows, but its ingestion step read both the ICS Advisory Project's master file (${n(B.input_rows_by_file_type.master)} rows) and its per-year files (${n(B.input_rows_by_file_type.per_year)} rows). The master file is a superset of the per-year files, so every CVE-advisory pair appears twice. This report keeps only master-file rows and drops ${n(B.within_master_duplicate_pairs_dropped)} further repeated pairs within that file, leaving **${n(B.rows_after_dedup)} unique CVE-advisory pairs across ${n(B.advisories_total)} advisories**. The QA report confirms that no pair is lost. Counts published with v1.1 itself should be read as roughly double the unique totals. A corrected dataset release is listed in the series' next steps.`));
add(L.H2("2.3 Scope: what counts as ONG-relevant and US-relevant"));
add(L.P(`An advisory is **ONG-relevant** if CISA tags it with the Energy sector (the sector that contains oil and natural gas) or "oil and gas", or if the v1.1 product taxonomy maps any of its products to an ONG process-control class (ONG-specific product lines such as flow computers and tank gauging; PLC, RTU and SCADA platforms common in production, pipelines and refining). It is **US-relevant** if CISA's distribution field includes the United States, worldwide or an unspecified multi-country footprint. EV-charging platforms and chargers, which CISA also tags as Energy but which are not ONG operational technology, are excluded.`));
add(L.P(`Applied to all ${n(B.advisories_total)} advisories, the sector test admits ${n(SC.sector_energy_or_oilgas)}, the product-class test ${n(SC.ong_class_mapped)} (${n(SC.both)} pass both), ${n(SC.excluded_for_non_us_distribution)} are removed for non-US distribution and ${n(SC.excluded_non_ong_energy_ev_charging)} for EV charging (${n(SC.excluded_non_ong_energy_ev_charging_edition_year_ytd)} of them in ${Y}). This leaves **${n(B.advisories_in_scope)} ONG-relevant advisories**. In ${W} ${Y} they are ${p(S.universe_ytd_current.in_scope_advisory_share_pct)} of all ${n(S.universe_ytd_current.advisories)} CISA ICS advisories. Every threshold and pattern is set in config/scope.json.`));
add(L.H2("2.4 Windows and units"));
add(L.P(`The snapshot's last advisory was published on ${S.snapshot_cutoff}, so the ${Y} edition covers ${W} ${Y}, and every other year is measured over the same window. Full-year figures are shown only for ${S.trend[0].year}-${Y1}. Two units are used. **Advisory-level** measures (CISA severity, advisory CVSS, CWE) count each advisory once, because CISA publishes severity and weakness classes per advisory rather than per CVE. **CVE-level** measures (KEV, EPSS, SSVC, remediation text, priority tier) count each unique CVE once within the scope and window described; a CVE listed in several advisories takes its earliest publication date and its strongest exploitation evidence.`));
add(L.H2("2.5 Exploitation-first priority tiers"));
add(L.P(`Each CVE is assigned to one of four tiers. The tiers put evidence of exploitation ahead of severity, following the logic of CISA's KEV and SSVC guidance.`));
add(L.NUM1(`**Tier 1**: listed in CISA KEV (exploitation confirmed).`));
add(L.NUM1(`**Tier 2**: not in KEV, but CISA's SSVC "Exploitation" decision point is _active_ or _poc_, or the CVE's EPSS percentile is at least ${S.config.tier2_epss_percentile} (top ${Math.round((1 - S.config.tier2_epss_percentile) * 100)}% of all scored CVEs).`));
add(L.NUM1(`**Tier 3**: no exploitation evidence, but the advisory is rated Critical.`));
add(L.NUM1(`**Tier 4**: everything else.`));
add(L.P(`KEV, EPSS and SSVC are applied as of ${S.input.sources_pulled} to every year. Older CVEs have therefore had longer to accumulate exploitation evidence than ${Y} CVEs, which is why the tier comparison in Section 3.3 is limited to adjacent years.`));
add(L.PB());

// ---------------- 3 findings ----------------
add(L.H1(`3. Findings`));
add(L.P(`Table 1 summarises the ${Y} window against the same window of ${Y1} and against ${Y1} as a whole.`));
const row = (lab, k, fmt = n) => [lab, fmt(cu[k]), fmt(pr[k]), fmt(fy[k])];
add(L.TABLE(["Measure (ONG-relevant scope)", `${Y}, ${W}`, `${Y1}, ${W}`, `${Y1}, full year`], [
  row("Advisories", "advisories"),
  row(`Advisories listing <= ${S.config.mega_threshold} CVEs`, "advisories_excl_mega"),
  row("Vendors", "vendors"),
  row("Unique CVEs", "unique_cves"),
  row(`Unique CVEs outside roll-up advisories`, "unique_cves_excl_mega"),
  row("Advisories rated Critical", "severity_critical_pct", p),
  row("Median advisory CVSS", "median_advisory_cvss", (x) => (x == null ? "n/a" : Number(x).toFixed(1))),
  row("CVEs in CISA KEV", "kev_cves"),
  row(`CVEs with EPSS >= ${S.config.epss_high_threshold}`, "epss_ge_threshold"),
  row("CVEs with CISA SSVC exploitation = active", "ssvc_active"),
  row("CVEs with CISA SSVC exploitation = poc", "ssvc_poc"),
  row("CVEs in Tier 1 or 2", "tier12"),
  row("CVEs with machine-readable remediation text", "remediation_text_pct", p),
  row("CVEs with explicit no-fix statement", "no_patch_cves"),
], [3960, 1800, 1800, 1800]));
add(L.CAP(`Table 1. Headline measures. Percentages are shares of advisories (severity) or of unique CVEs (remediation text). Source: report/stats.json.`));

add(L.H2("3.1 Volume"));
add(L.P(`Disclosed ONG-relevant exposure has grown in steps rather than smoothly (Figure 1). Full-year advisory counts ranged between ${n(Math.min(...S.trend.filter(r => r.advisories_full_year).map(r => r.advisories_full_year)))} and ${n(Math.max(...S.trend.filter(r => r.advisories_full_year).map(r => r.advisories_full_year)))} over ${S.trend[0].year}-${Y1}, with the largest full year in ${ts.peak_full_year} (${n(ts.peak_full_year_advisories)}). On the fixed ${W} window, ${Y} is the highest year in the series (${n(cu.advisories)}), ${sg(ts.ytd_growth_since_2021_pct)} above 2021 (${n(ts.advisories_ytd_2021)}).`));
add(L.FIG(path.join(FIGDIR, "fig1_advisories_by_year.png"), `Figure 1. ONG-relevant advisories per year. Blue: full calendar year (${S.trend[0].year}-${Y1}). Orange: ${W} only, the like-for-like window used for ${Y}.`));
add(L.P(`CVE counts need more care (Figure 2). A small number of advisories bundle hundreds of CVEs, usually open-source and third-party components shipped inside a single firmware image or appliance. In ${Y}, ${n(cu.mega_advisories)} such roll-ups account for most of the rise to ${n(cu.unique_cves)} unique CVEs. Outside them the count grew ${sg(yoy.unique_cves_excl_mega)}. A year-over-year CVE figure without that split overstates how fast new, distinct weaknesses are appearing. It does show something real, though: component inventories inside OT products are large, and a single product line can carry hundreds of inherited CVEs at once.`));
add(L.FIG(path.join(FIGDIR, "fig2_cves_by_year.png"), `Figure 2. Unique CVEs in ONG-relevant advisories over the same ${W} window each year, split by whether a CVE appears only in roll-up advisories (more than ${S.config.mega_threshold} CVEs each).`));

add(L.H2("3.2 Severity"));
add(L.P(`${p(cu.severity_critical_pct)} of ${Y} ONG-relevant advisories are rated Critical by CISA and ${p(cu.severity_critical_or_high_pct)} are Critical or High, with a median advisory CVSS of ${cu.median_advisory_cvss == null ? "n/a" : Number(cu.median_advisory_cvss).toFixed(1)}. The severity mix has been broadly stable since 2017 (Figure 3), so severity alone does little to separate one year's exposure from another, or one advisory from the next. This is the case for the exploitation-first ordering below.`));
add(L.FIG(path.join(FIGDIR, "fig3_severity_mix.png"), `Figure 3. CISA severity labels on ONG-relevant advisories, 2016-${Y} (${Y}: ${W}). The label above each bar is the Critical share.`));

add(L.H2("3.3 Exploitation evidence and priority tiers"));
add(L.P(`Against ${n(cu.unique_cves)} unique CVEs, ${n(cu.kev_cves)} are known exploited (Tier 1) and a further ${n(cu.tier_counts.tier2)} carry SSVC or EPSS evidence of exploitation activity (Tier 2). ${n(cu.tier_counts.tier3)} sit in Critical advisories with no exploitation evidence (Tier 3), and ${n(cu.tier_counts.tier4)} are in Tier 4 (Figure 4). The Tier 1-2 share fell from ${p(pr.tier12_pct)} to ${p(cu.tier12_pct)} between the two windows. Part of that fall is timing: exploitation evidence accumulates after publication, and CISA's SSVC decision points cover ${p(cu.ssvc_present_pct)} of ${Y} CVEs against ${p(pr.ssvc_present_pct)} of ${Y1} CVEs at the same pull date. Part is dilution: the roll-up advisories add many CVEs that have little exploitation activity. The ${Y} figure should be re-read in the ${Y + 1} edition, once it has matured.`));
add(L.FIG(path.join(FIGDIR, "fig4_priority_tiers.png"), `Figure 4. Priority tiers as shares of unique ONG-relevant CVEs in each window; counts are shown on the bars. Tier definitions are in Section 2.5.`));
add(L.P(`Table 2 lists the ${n(cu.kev_cves)} KEV-listed CVEs. ${ka.third_party === cu.kev_cves ? 'All of them are' : `${n(ka.third_party)} of them are`} attributed to software the OT vendor did not write: the Linux kernel's crypto interface, a document database, a browser engine, an SSH server library, a PHP runtime and a firewall operating system hosted on an industrial appliance. ${n(ka.in_mega_advisories)} of the ${n(cu.kev_cves)} sit in roll-up advisories. For ONG operators the practical point is that the exposure most likely to be exploited sits in the IT software shipped inside OT products, and the vendor's own OT firmware accounts for none of it here. A software bill of materials that reaches those embedded components is the input needed to find it.`));
add(L.TABLE(["CVE", "Advisory", "Vendor / product", "Embedded component", "EPSS"],
  S.kev_ytd_table.map((r) => [r.cve_id, r["ICS-CERT_Number"], `${r.Vendor}: ${String(r.Product).replace(r.Vendor + " ", "")}`, r.component || "not attributed", r.epss === "" ? "n/a" : Number(r.epss).toFixed(3)]),
  [1500, 1450, 2700, 2810, 900]));
add(L.CAP(`Table 2. KEV-listed CVEs in ONG-relevant ${Y} advisories (${W}). Component attributions are in config/kev_component_attribution.csv${ka.all_author_verified ? ' and were each confirmed against the NVD record by the authors.' : ' and must be confirmed against each CVE record before release.'}`));

add(L.H2("3.4 Vendor concentration"));
add(L.P(`Exposure disclosure is concentrated among a handful of automation majors (Figure 5), but less so than a year earlier. ${vc.top1_vendor} alone published ${p(vc.top1_share_pct)} of ${Y} ONG-relevant advisories, and the top five published ${p(vc.top5_share_pct)}. The number of distinct vendors rose to ${n(cu.vendors)}, and the Herfindahl-Hirschman index of advisory counts fell from ${n(vc.hhi_ytd_prior)} to ${n(vc.hhi_ytd_current)}. More vendors are entering the public disclosure process, which widens the set of suppliers an ONG asset owner must track. Advisory counts partly reflect vendor maturity: firms with established product security teams publish more. A high count is not evidence of weaker products.`));
add(L.FIG(path.join(FIGDIR, "fig5_top_vendors.png"), `Figure 5. Top ten vendors by ONG-relevant advisories in ${Y} (${W}); the number of CVEs across those advisories is shown in brackets.`));

add(L.H2("3.5 Weakness classes"));
add(L.P(`CWE-306, missing authentication for a critical function, leads ${Y} with a ${p(c306.ytd_current_pct)} share of advisories, against ${p(c306.hist_pct)} over ${S.trend[0].year}-${Y1} (Figure 6). It is also first when roll-up advisories are excluded (the top three then are ${S.cwes_ytd_excl_mega_top3.join(", ")}). For ONG networks this is the most directly actionable class. A function reachable without authentication is exposed to anyone who can reach the device, so network segmentation and remote-access control, not only patching, determine real exposure. Memory-safety classes (out-of-bounds write and read, integer overflow, use-after-free, NULL dereference) also rose above their historical shares. Generic input validation (CWE-20) fell well below its historical share, which may reflect more specific CWE assignment in recent advisories rather than fewer input-handling flaws.`));
add(L.FIG(path.join(FIGDIR, "fig6_top_cwes.png"), `Figure 6. Share of ONG-relevant advisories citing each CWE in ${Y} (blue) against ${S.trend[0].year}-${Y1} (orange). An advisory is counted once per CWE it cites.`));

add(L.H2("3.6 Remediation signal, product classes and threat context"));
add(L.P(`**Remediation.** Whether a fix exists is the question operators most need answered, and the public record answers it poorly. CNA-supplied solution or workaround text is present in the CVE record for ${p(cu.remediation_text_pct)} of in-scope ${Y} CVEs. ${n(cu.no_patch_cves)} CVEs carry an explicit statement that no fix is or will be available. CISA's advisory pages usually contain mitigation text, but the machine-readable mirror used here does not carry it. The series treats "no remediation text" as _unknown_, not as _patched_.`));
add(L.P(`**Product classes.** Among ${Y} in-scope CVEs, ${n(cu.ong_class_counts.plc || 0)} map to process-control PLC platforms, ${n(cu.ong_class_counts.rtu || 0)} to RTUs, ${n(cu.ong_class_counts.scada || 0)} to SCADA platforms and ${n(cu.ong_class_counts.ong_product_line || 0)} to ONG-specific product lines; ${n(cu.ong_class_counts.unmapped || 0)} fall outside the curated taxonomy. The ONG-specific product-line count is small in every year. That reflects how rarely ONG-exclusive products (flow computers, tank gauging, gas chromatographs) appear in advisories relative to shared automation platforms, rather than an absence of risk in them.`));
add(L.P(`**Threat context.** ${n(cu.attack_matched_cves)} in-scope ${Y} CVEs are in products that a MITRE ATT&CK for ICS software profile names directly (${cu.attack_entities.join(", ") || "none"}), through the CODESYS runtime used across several PLC families. INCONTROLLER (also reported as PIPEDREAM) is a publicly documented ICS attack toolkit built to target programmable controllers, including CODESYS-based devices. The overlap is a pointer to where a known capability meets disclosed weaknesses. It is not evidence of use against these CVEs. Compensating controls from CISA's Cross-Sector Performance Goals map to ${p(cu.cpg_mapped_pct)} of in-scope ${Y} CVEs through their product class.`));
add(L.PB());

// ---------------- 4 implications ----------------
add(L.H1("4. What the measurements imply"));
add(L.P(`The findings suggest four practical readings. They are implications of the data, not prescriptive guidance.`));
add(L.BUL(`**For operators: triage by exploitation evidence first.** In ${Y}, ${p(cu.tier12_pct)} of ONG-relevant CVEs carry any exploitation evidence. Working Tier 1-2 first (${n(cu.tier12)} CVEs) and then Critical advisories gives a much shorter first queue than ranking by severity alone, which would put ${n(cu.cves_in_critical_or_high_advisories)} CVEs from Critical or High advisories at the front.`));
add(L.BUL(`**For operators and vendors: inventory what is inside the box.** Known-exploited exposure in ${Y} came through embedded third-party components. Component-level SBOMs for OT products, and procurement terms that require them, are the control that matches this finding.`));
add(L.BUL(`**For regulators: count advisories, not raw CVEs, and publish the window.** Raw CVE totals doubled while distinct advisories and non-roll-up CVEs grew modestly. Metrics in pipeline and energy-sector security reporting should state their unit and time window, or they will describe roll-up packaging rather than risk.`));
add(L.BUL(`**For researchers: the remediation gap is the measurement gap.** Machine-readable fix status covers a small fraction of ONG-relevant CVEs. Structured remediation data in CSAF advisories, joined at scale, is the next improvement the series needs.`));

// ---------------- 5 limitations ----------------
add(L.H1("5. Limitations"));
[
  `**Disclosed, not deployed.** Advisory counts measure what vendors and CISA disclose. They say nothing about how many affected products run in US ONG facilities, or how many are patched. Vendors with mature disclosure programs appear more often.`,
  `**Scope is a proxy.** CISA's Energy tag covers electricity as well as oil and natural gas, and the product taxonomy is a curated allowlist. Some electricity-only products remain in scope, and some ONG-used products tagged only "Critical Manufacturing" and not in the taxonomy are excluded. The EV-charging exclusion is pattern-based.`,
  `**Advisory-level severity and CWE.** CISA publishes severity and CWE per advisory. A roll-up advisory contributes many CWEs, and all of its CVEs inherit its severity.`,
  `**Point-in-time enrichment.** KEV, EPSS and SSVC are as of ${S.input.sources_pulled}, and recent CVEs have had less time to acquire exploitation evidence or SSVC coverage.`,
  `**Mirror dependency.** Advisories come through the ICS Advisory Project mirror (ODbL). Transcription differences from CISA's pages are possible, and the spot checks in the QA report are the control for them.`,
  `**Partial year.** The ${Y} edition covers ${W}. The annual rebuild in December will extend the window to year end, and every number here will change.`,
  `**KEV component attribution.** The attribution of KEV-listed CVEs to embedded components is a manual reading of CVE descriptions, recorded CVE by CVE in config/kev_component_attribution.csv${ka.all_author_verified ? ' and checked by the authors against NVD' : ' for verification'}. It identifies the component, not whether the OT product's configuration exposes it.`,
].forEach((t) => add(L.NUM2(t)));

// ---------------- 6 reproducibility ----------------
add(L.H1("6. Reproducibility and the series plan"));
add(L.P(`Every number in this report is read from report/stats.json, which code/03_stats_qa.py writes, and every figure is drawn from the same file. Running the numbered scripts in code/ against the frozen snapshot rebuilds the report. The repository's README gives the commands. The QA report (data/processed/qa_report.txt) records row counts at each stage, range checks and ten named spot checks against CISA advisory pages. Each annual edition will be released as a new version under one Zenodo concept DOI, with the prior edition's configuration unchanged unless a change is documented in the release notes.`));

// ---------------- back matter ----------------
add(L.H1("Declarations"));
add(L.P(`**Data availability.** Input: doi:${S.input.doi}. Code, configuration, derived tables and this report: ${M.repository} and ${doi}.`));
add(L.P(`**Author contributions (CRediT).** ${people.map((a) => `${a.name}: ${a.roles.join(", ")}`).join(". ")}.`));
add(L.P(`**Competing interests.** None declared.`));
add(L.P(`**Funding.** No external funding.`));
add(L.P(`**Use of AI tools.** An AI assistant (Claude, Anthropic) was used to write analysis code, draft figures and draft text. The authors specified the analysis, made every scope and threshold decision recorded in config/scope.json, verified the numbers against the QA report and CISA source pages, and take full responsibility for the content.`));
add(L.H1("References"));
[
  `Ikwuogu, F. O., Abutu, S., and Orimogunje, A. (${Y}). ONG-OT Vulnerability Prioritization Dataset, v1.1. Zenodo. https://doi.org/${S.input.doi}`,
  `ICS Advisory Project. CISA ICS advisory dataset (ODbL v1.0). https://github.com/icsadvprj/ICS-Advisory-Project`,
  `Cybersecurity and Infrastructure Security Agency. Known Exploited Vulnerabilities Catalog. https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
  `Cybersecurity and Infrastructure Security Agency. Vulnrichment. https://github.com/cisagov/vulnrichment`,
  `Cybersecurity and Infrastructure Security Agency. Stakeholder-Specific Vulnerability Categorization (SSVC). https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc`,
  `Jacobs, J., Romanosky, S., Edwards, B., Adjerid, I., and Roytman, M. (2021). Exploit Prediction Scoring System (EPSS). Digital Threats: Research and Practice, 2(3). https://doi.org/10.1145/3436242`,
  `FIRST. Exploit Prediction Scoring System. https://www.first.org/epss/`,
  `MITRE. ATT&CK for ICS. https://attack.mitre.org/matrices/ics/`,
  `MITRE. Common Weakness Enumeration. https://cwe.mitre.org/`,
  `Cybersecurity and Infrastructure Security Agency. Cross-Sector Cybersecurity Performance Goals. https://www.cisa.gov/cross-sector-cybersecurity-performance-goals`,
].forEach((t) => add(L.NUM3(t)));

// ---------------- appendix ----------------
add(L.PB());
add(L.H1("Appendix A. Year-by-year series"));
add(L.TABLE(["Year", "Advisories (full year)", `Advisories (${W})`, `Unique CVEs (${W})`, "Critical %", "Vendors"],
  S.trend.map((r) => [String(r.year), r.advisories_full_year == null ? "n/a" : n(r.advisories_full_year), n(r.advisories_ytd), n(r.cves_ytd), r.critical_pct == null ? "n/a" : p(r.critical_pct), n(r.vendors)]),
  [1100, 1900, 1800, 1900, 1360, 1300]));
add(L.CAP(`Table A1. Series values; the full table with additional columns is report/tables/t1_trend_by_year.csv. Critical % and vendors are for the full year (${Y}: ${W}).`));

L.build({ outFile: path.join(ROOT, "report", `ONG_OT_Exposure_Report_${Y}${FINAL ? "" : "_DRAFT"}.docx`), children: kids, draft: !FINAL, runningTitle: M.title })
  .then((f) => console.log("wrote", f));
