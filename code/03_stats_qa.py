#!/usr/bin/env python3
"""Step 3 - compute every number the report quotes, write stats.json, tables and the QA report.

Reads  data/processed/{cve_advisory_pairs,advisories}.csv, build_log.json, config/scope.json
Writes report/stats.json            (the ONLY source of numbers for the report text)
       report/tables/*.csv          (tables reproduced in the report)
       data/processed/qa_report.txt (read this before trusting anything)

Unit conventions (stated in the report's methods):
  - advisory-level measures (severity, CVSS, CWE) count each CISA advisory once, because
    CISA publishes severity and CWE per advisory, not per CVE;
  - CVE-level measures (KEV, EPSS, SSVC, no-patch, priority tier) count each unique CVE once
    within the scope and window being described.
"""
import json
import os
from collections import Counter

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "data", "processed")
T = os.path.join(ROOT, "report", "tables")
CFG = json.load(open(os.path.join(ROOT, "config", "scope.json"), encoding="utf-8"))
LOG = json.load(open(os.path.join(P, "build_log.json"), encoding="utf-8"))
Y = CFG["windows"]["edition_year"]
Y0 = CFG["windows"]["trend_start_year"]
os.makedirs(T, exist_ok=True)


def pct(n, d):
    return round(100.0 * n / d, 1) if d else None


def load():
    pairs = pd.read_csv(os.path.join(P, "cve_advisory_pairs.csv"), low_memory=False, parse_dates=["release_date"])
    adv = pd.read_csv(os.path.join(P, "advisories.csv"), low_memory=False, parse_dates=["release_date"])
    for c in ["in_scope", "in_ytd_window", "known_exploited", "no_patch_available", "mega_advisory",
              "vulnrichment_remediation_text_present"]:
        if c in pairs:
            pairs[c] = pairs[c].astype(str).str.lower().eq("true")
    for c in ["in_scope", "in_ytd_window", "any_kev", "mega_advisory"]:
        adv[c] = adv[c].astype(str).str.lower().eq("true")
    # 'Not Applicable' / 'Not Assigned' CVSS labels become missing, not zero
    adv["cumulative_cvss"] = pd.to_numeric(adv["cumulative_cvss"], errors="coerce")
    for c in ["epss", "percentile"]:
        pairs[c] = pd.to_numeric(pairs[c], errors="coerce")
    return pairs, adv


def cve_frame(pairs):
    """Collapse pairs to one row per CVE (a CVE can sit in several advisories). A CVE takes the
    earliest in-window release, and its worst tier / any-KEV / max-EPSS across its advisories."""
    p = pairs.dropna(subset=["cve_id"])
    g = p.groupby("cve_id")
    return pd.DataFrame({
        "first_release": g["release_date"].min(),
        "known_exploited": g["known_exploited"].any(),
        "epss": g["epss"].max(),
        "percentile": g["percentile"].max(),
        "ssvc": g["ssvc_exploitation"].agg(lambda s: next((x for x in ["active", "poc", "none"] if x in set(s.dropna())), "")),
        "ssvc_present": g["ssvc_exploitation"].agg(lambda s: s.fillna("").ne("").any()),
        "remediation_text": g["vulnrichment_remediation_text_present"].any(),
        "no_patch": g["no_patch_available"].any(),
        "tier": g["priority_tier"].min(),
        "only_mega": g["mega_advisory"].all(),
        "ong_class": g["ong_product_class"].agg(lambda s: next((x for x in ["ong_product_line", "rtu", "scada", "plc"] if x in set(s)), "unmapped")),
        "cpg_mapped": g["cpg2_applicable_controls"].agg(lambda s: s.fillna("").str.contains(r"\d\.[A-Z]").any()),
        "attack_entity": g["attack_ics_matched_entity"].agg(lambda s: ";".join(sorted(set(s.dropna())))),
    }).reset_index()


def window(pairs, adv, year, ytd):
    ps = pairs[(pairs.release_year == year) & pairs.in_scope]
    ad = adv[(adv.release_year == year) & adv.in_scope]
    if ytd:
        ps, ad = ps[ps.in_ytd_window], ad[ad.in_ytd_window]
    return ps, ad


def block(ps, ad):
    c = cve_frame(ps)
    n = len(c)
    sev = ad["cvss_severity"].fillna("Not stated").value_counts()
    tiers = c["tier"].value_counts().reindex([1, 2, 3, 4], fill_value=0)
    thr = CFG["epss_high_threshold"]
    return {
        "advisories": int(len(ad)),
        "advisories_excl_mega": int((~ad.mega_advisory).sum()),
        "mega_advisories": int(ad.mega_advisory.sum()),
        "unique_cves": int(n),
        "unique_cves_excl_mega": int((~c.only_mega).sum()),
        "vendors": int(ad["vendor"].nunique()),
        "median_cves_per_advisory": float(ad["n_cves"].median()) if len(ad) else None,
        "severity_counts": {k: int(v) for k, v in sev.items()},
        "severity_critical_pct": pct(int(sev.get("Critical", 0)), len(ad)),
        "severity_critical_or_high_pct": pct(int(sev.get("Critical", 0) + sev.get("High", 0)), len(ad)),
        "median_advisory_cvss": float(ad["cumulative_cvss"].median()) if ad["cumulative_cvss"].notna().any() else None,
        "kev_cves": int(c.known_exploited.sum()),
        "kev_pct": pct(int(c.known_exploited.sum()), n),
        "kev_advisories": int(ad.any_kev.sum()),
        "epss_scored": int(c.epss.notna().sum()),
        "epss_median": round(float(c.epss.median()), 5) if c.epss.notna().any() else None,
        "epss_ge_threshold": int((c.epss >= thr).sum()),
        "epss_ge_threshold_pct": pct(int((c.epss >= thr).sum()), int(c.epss.notna().sum())),
        "epss_pctl_ge_095": int((c.percentile >= 0.95).sum()),
        "ssvc_present": int(c.ssvc_present.sum()),
        "ssvc_present_pct": pct(int(c.ssvc_present.sum()), n),
        "ssvc_active": int((c.ssvc == "active").sum()),
        "ssvc_poc": int((c.ssvc == "poc").sum()),
        "ssvc_none": int((c.ssvc == "none").sum()),
        "remediation_text_pct": pct(int(c.remediation_text.sum()), n),
        "no_patch_cves": int(c.no_patch.sum()),
        "tier_counts": {f"tier{k}": int(v) for k, v in tiers.items()},
        "tier_pct": {f"tier{k}": pct(int(v), n) for k, v in tiers.items()},
        "tier12": int(c.tier.isin([1, 2]).sum()),
        "cves_in_critical_or_high_advisories": int(ps[ps["CVSS_Severity"].isin(["Critical", "High"])].cve_id.nunique()),
        "tier12_pct": pct(int(c.tier.isin([1, 2]).sum()), n),
        "tier12_no_patch": int((c.tier.isin([1, 2]) & c.no_patch).sum()),
        "tier12_in_mega_only": int((c.tier.isin([1, 2]) & c.only_mega).sum()),
        "ong_class_counts": {k: int(v) for k, v in c.ong_class.value_counts().items()},
        "cpg_mapped_pct": pct(int(c.cpg_mapped.sum()), n),
        "attack_matched_cves": int(c.attack_entity.ne("").sum()),
        "attack_entities": sorted({e for s in c.attack_entity for e in s.split(";") if e}),
    }


def top_vendors(ad, k=10):
    t = ad.groupby("vendor").agg(advisories=("ICS-CERT_Number", "count"), cves=("n_cves", "sum"),
                                 kev_advisories=("any_kev", "sum")).sort_values(["advisories", "cves"], ascending=False)
    t["share_pct"] = (100 * t.advisories / t.advisories.sum()).round(1)
    return t.head(k).reset_index()


def hhi(ad):
    s = ad["vendor"].value_counts(normalize=True)
    return round(float((s ** 2).sum() * 10000), 0)


def top_cwes(ad, k=10):
    cnt = Counter()
    for s in ad["cwes"].fillna(""):
        cnt.update([c for c in s.split(";") if c])
    n = len(ad)
    return pd.DataFrame([{"cwe": c, "advisories": v, "share_pct": pct(v, n)} for c, v in cnt.most_common(k)])


CWE_NAMES = {  # MITRE CWE short names, for table labels only
    "CWE-20": "Improper input validation", "CWE-22": "Path traversal", "CWE-78": "OS command injection",
    "CWE-79": "Cross-site scripting", "CWE-89": "SQL injection", "CWE-94": "Code injection",
    "CWE-119": "Improper restriction of operations within memory buffer", "CWE-120": "Classic buffer overflow",
    "CWE-121": "Stack-based buffer overflow", "CWE-122": "Heap-based buffer overflow", "CWE-125": "Out-of-bounds read",
    "CWE-190": "Integer overflow", "CWE-200": "Exposure of sensitive information", "CWE-269": "Improper privilege management",
    "CWE-276": "Incorrect default permissions", "CWE-284": "Improper access control", "CWE-285": "Improper authorization",
    "CWE-287": "Improper authentication", "CWE-306": "Missing authentication for critical function",
    "CWE-311": "Missing encryption of sensitive data", "CWE-319": "Cleartext transmission", "CWE-321": "Hard-coded cryptographic key",
    "CWE-327": "Broken or risky cryptographic algorithm", "CWE-352": "Cross-site request forgery", "CWE-400": "Uncontrolled resource consumption",
    "CWE-401": "Missing release of memory", "CWE-416": "Use after free", "CWE-427": "Uncontrolled search path element",
    "CWE-476": "NULL pointer dereference", "CWE-502": "Deserialization of untrusted data", "CWE-522": "Insufficiently protected credentials",
    "CWE-611": "XML external entity reference", "CWE-668": "Exposure of resource to wrong sphere", "CWE-703": "Improper check of exceptional conditions",
    "CWE-732": "Incorrect permission assignment", "CWE-754": "Improper check for unusual conditions", "CWE-770": "Allocation without limits",
    "CWE-787": "Out-of-bounds write", "CWE-798": "Hard-coded credentials", "CWE-862": "Missing authorization",
    "CWE-863": "Incorrect authorization", "CWE-1321": "Prototype pollution", "CWE-295": "Improper certificate validation",
    "CWE-399": "Resource management errors", "CWE-362": "Race condition", "CWE-617": "Reachable assertion",
    "CWE-835": "Infinite loop", "CWE-434": "Unrestricted file upload", "CWE-601": "Open redirect", "CWE-918": "Server-side request forgery",
    "CWE-1333": "Inefficient regular expression", "CWE-404": "Improper resource shutdown", "CWE-674": "Uncontrolled recursion",
    "CWE-129": "Improper validation of array index", "CWE-307": "Improper restriction of excessive authentication attempts",
    "CWE-613": "Insufficient session expiration", "CWE-1188": "Insecure default initialization of resource", "CWE-252": "Unchecked return value", "CWE-367": "TOCTOU race condition",
}


def main():
    pairs, adv = load()
    ytd_end = CFG["windows"]["ytd_end_month_day"]
    S = {"edition": Y, "snapshot_cutoff": CFG["windows"]["snapshot_cutoff"], "ytd_label": f"1 Jan - {pd.Timestamp('2000-' + ytd_end).strftime('%-d %b')}",
         "build": LOG, "config": {"epss_high_threshold": CFG["epss_high_threshold"],
                                  "tier2_epss_percentile": CFG["priority_tiers"]["tier2_epss_percentile"],
                                  "mega_threshold": CFG["mega_advisory_cve_threshold"]},
         "input": {"dataset": "ONG-OT Vulnerability Prioritization Dataset v1.1", "doi": "10.5281/zenodo.22729882",
                   "sources_pulled": "2026-09-12"}}

    cur_p, cur_a = window(pairs, adv, Y, ytd=True)
    prv_p, prv_a = window(pairs, adv, Y - 1, ytd=True)
    S["ytd_current"] = block(cur_p, cur_a)
    S["ytd_prior"] = block(prv_p, prv_a)
    fy_p, fy_a = window(pairs, adv, Y - 1, ytd=False)
    S["full_prior_year"] = block(fy_p, fy_a)

    # all-time in-scope baseline (every advisory ever, EPSS/KEV as of snapshot)
    S["all_in_scope"] = block(pairs[pairs.in_scope], adv[adv.in_scope])

    def chg(a, b):
        return round(100.0 * (a - b) / b, 1) if b else None
    cu, pr = S["ytd_current"], S["ytd_prior"]
    S["yoy"] = {k: chg(cu[k], pr[k]) for k in ["advisories", "unique_cves", "advisories_excl_mega", "unique_cves_excl_mega", "vendors", "kev_cves"]}

    # comparator: whole CISA ICS universe in the same window
    all_cur = adv[(adv.release_year == Y) & adv.in_ytd_window]
    all_cur_p = pairs[(pairs.release_year == Y) & pairs.in_ytd_window]
    S["universe_ytd_current"] = {"advisories": int(len(all_cur)), "unique_cves": int(all_cur_p.cve_id.nunique()),
                                 "in_scope_advisory_share_pct": pct(cu["advisories"], len(all_cur))}

    # --- trend table -------------------------------------------------------
    rows = []
    for yr in range(Y0, Y + 1):
        pf, af = window(pairs, adv, yr, ytd=False)
        py, ay = window(pairs, adv, yr, ytd=True)
        cf = cve_frame(pf)
        rows.append({"year": yr, "advisories_full_year": int(len(af)) if yr < Y else None,
                     "advisories_ytd": int(len(ay)), "cves_full_year": int(len(cf)) if yr < Y else None,
                     "cves_ytd": int(py.cve_id.nunique()),
                     "cves_ytd_excl_mega": int(py[~py.mega_advisory].cve_id.nunique()),
                     "critical_pct": pct(int((af.cvss_severity == "Critical").sum()), len(af)),
                     "high_pct": pct(int((af.cvss_severity == "High").sum()), len(af)),
                     "medium_pct": pct(int((af.cvss_severity == "Medium").sum()), len(af)),
                     "low_pct": pct(int((af.cvss_severity == "Low").sum()), len(af)),
                     "kev_pct_of_cves": pct(int(cf.known_exploited.sum()), len(cf)),
                     "vendors": int(af.vendor.nunique())})
    trend = pd.DataFrame(rows)
    trend.to_csv(os.path.join(T, "t1_trend_by_year.csv"), index=False)
    S["trend"] = rows
    full = trend[trend.year < Y]
    S["trend_summary"] = {
        "peak_full_year": int(full.loc[full.advisories_full_year.idxmax(), "year"]),
        "peak_full_year_advisories": int(full.advisories_full_year.max()),
        "ytd_rank_current": int(trend.advisories_ytd.rank(ascending=False, method="min")[trend.year == Y].iloc[0]),
        "ytd_years_compared": int(len(trend)),
        "advisories_ytd_2021": int(trend.loc[trend.year == 2021, "advisories_ytd"].iloc[0]),
        "ytd_growth_since_2021_pct": chg(cu["advisories"], int(trend.loc[trend.year == 2021, "advisories_ytd"].iloc[0])),
    }

    # --- vendors, CWEs -------------------------------------------------------
    tv = top_vendors(cur_a)
    tv.to_csv(os.path.join(T, "t2_top_vendors_ytd.csv"), index=False)
    S["vendors_ytd"] = tv.to_dict("records")
    S["vendor_concentration"] = {"hhi_ytd_current": hhi(cur_a), "hhi_ytd_prior": hhi(prv_a),
                                 "top5_share_pct": round(float(tv.head(5).share_pct.sum()), 1),
                                 "top1_vendor": tv.iloc[0]["vendor"], "top1_share_pct": float(tv.iloc[0]["share_pct"]),
                                 "hq_country_ytd": {k: int(v) for k, v in cur_a.hq_country.fillna("Not stated").value_counts().head(6).items()}}
    tc = top_cwes(cur_a)
    tc["name"] = tc.cwe.map(CWE_NAMES).fillna("see cwe.mitre.org")
    tc_prior = top_cwes(adv[adv.in_scope & (adv.release_year < Y) & (adv.release_year >= Y0)], k=100000)
    tc["share_pct_2012_2025"] = tc.cwe.map(dict(zip(tc_prior.cwe, tc_prior.share_pct))).fillna(0.0)
    tc.to_csv(os.path.join(T, "t3_top_cwes_ytd.csv"), index=False)
    S["cwes_ytd"] = tc.to_dict("records")
    S["cwe_306"] = {"ytd_current_advisories": int(tc.loc[tc.cwe == "CWE-306", "advisories"].sum()),
                    "ytd_current_pct": float(tc.loc[tc.cwe == "CWE-306", "share_pct"].sum()),
                    "hist_pct": float(tc.loc[tc.cwe == "CWE-306", "share_pct_2012_2025"].sum()),
                    "rank_ytd_current": int(tc.index[tc.cwe == "CWE-306"][0] + 1) if (tc.cwe == "CWE-306").any() else None}
    tc_nm = top_cwes(cur_a[~cur_a.mega_advisory])
    S["cwes_ytd_excl_mega_top3"] = tc_nm.head(3).cwe.tolist()

    # --- tiers table -------------------------------------------------------
    tier_rows = []
    for t in [1, 2, 3, 4]:
        tier_rows.append({"tier": t, "ytd_current": cu["tier_counts"][f"tier{t}"], "ytd_current_pct": cu["tier_pct"][f"tier{t}"],
                          "ytd_prior": pr["tier_counts"][f"tier{t}"], "ytd_prior_pct": pr["tier_pct"][f"tier{t}"],
                          "all_in_scope": S["all_in_scope"]["tier_counts"][f"tier{t}"]})
    pd.DataFrame(tier_rows).to_csv(os.path.join(T, "t4_priority_tiers.csv"), index=False)

    # KEV CVEs in the current window, listed for the author's spot check
    kc = cve_frame(cur_p)
    kev_list = cur_p[cur_p.cve_id.isin(kc.loc[kc.known_exploited, "cve_id"])][["cve_id", "ICS-CERT_Number", "Vendor", "Product", "epss", "ssvc_exploitation"]].drop_duplicates("cve_id")
    kev_list.to_csv(os.path.join(T, "t5_kev_cves_ytd.csv"), index=False)
    S["kev_ytd_list"] = kev_list.cve_id.tolist()
    attr = pd.read_csv(os.path.join(ROOT, "config", "kev_component_attribution.csv"))
    attr = attr[attr.cve_id.isin(S["kev_ytd_list"])]
    S["kev_ytd_attribution"] = {"third_party": int((attr.component_origin == "third_party").sum()),
                                "vendor_native": int((attr.component_origin == "vendor_native").sum()),
                                "unknown": int((attr.component_origin == "unknown").sum()) + len(set(S["kev_ytd_list"]) - set(attr.cve_id)),
                                "in_mega_advisories": int(cur_p[cur_p.known_exploited & cur_p.mega_advisory].cve_id.nunique()),
                                "all_author_verified": bool(attr.author_verified.eq("yes").all())}
    kt = kev_list.merge(attr[["cve_id", "component_origin", "component"]], on="cve_id", how="left")
    kt.to_csv(os.path.join(T, "t5_kev_cves_ytd.csv"), index=False)
    S["kev_ytd_table"] = kt.fillna("").to_dict("records")

    json.dump(S, open(os.path.join(ROOT, "report", "stats.json"), "w"), indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))

    # --- QA report -------------------------------------------------------
    q = []
    q.append(f"QA report - State of OT Vulnerability Exposure in US Oil and Natural Gas, {Y}")
    q.append(f"Generated by code/03_stats_qa.py from {S['input']['dataset']} (doi:{S['input']['doi']})\n")
    q.append("ROW COUNTS")
    for k in ["input_rows", "unique_pairs_in_input", "master_rows", "within_master_duplicate_pairs_dropped", "rows_after_dedup", "rows_without_cve_id", "advisories_total", "advisories_in_scope", "pairs_in_scope"]:
        q.append(f"  {k:45s} {LOG[k]}")
    q.append(f"  input rows by file type: {LOG['input_rows_by_file_type']}")
    q.append(f"  scope components (advisories): {LOG['scope_components_advisories']}")
    ok_dup = LOG["input_rows"] == 2 * LOG["master_rows"] and LOG["unique_pairs_in_input"] == LOG["rows_after_dedup"]
    q.append(f"  CHECK duplicate structure (input = 2 x master, unique pairs preserved): {'PASS' if ok_dup else 'FAIL'}")
    q.append("\nRANGE / SANITY CHECKS")
    viol_epss = int(((pairs.epss < 0) | (pairs.epss > 1)).sum())
    viol_cvss = int(((adv.cumulative_cvss < 0) | (adv.cumulative_cvss > 10)).sum())
    q.append(f"  EPSS outside [0,1]: {viol_epss}  {'PASS' if viol_epss == 0 else 'FAIL'}")
    q.append(f"  advisory CVSS outside [0,10]: {viol_cvss}  {'PASS' if viol_cvss == 0 else 'FAIL'}")
    q.append(f"  max release date = snapshot cutoff: {LOG['max_release_date']} vs {CFG['windows']['snapshot_cutoff']}  {'PASS' if LOG['max_release_date'] == CFG['windows']['snapshot_cutoff'] else 'FAIL'}")
    tier_sum = sum(cu["tier_counts"].values())
    q.append(f"  tiers sum to unique CVEs ({tier_sum} vs {cu['unique_cves']}): {'PASS' if tier_sum == cu['unique_cves'] else 'FAIL'}")
    sev_sum = sum(cu["severity_counts"].values())
    q.append(f"  severity counts sum to advisories ({sev_sum} vs {cu['advisories']}): {'PASS' if sev_sum == cu['advisories'] else 'FAIL'}")
    q.append(f"  KEV CVEs listed in t5 ({len(kev_list)}) = stats kev_cves ({cu['kev_cves']}): {'PASS' if len(kev_list) == cu['kev_cves'] else 'FAIL'}")
    q.append(f"  EPSS coverage {Y} YTD in scope: {cu['epss_scored']}/{cu['unique_cves']} CVEs scored")
    q.append("\nHEADLINE NUMBERS (every one appears in the report; check the report against these)")
    for k in ["advisories", "unique_cves", "vendors", "severity_critical_pct", "kev_cves", "epss_ge_threshold", "no_patch_cves"]:
        q.append(f"  {Y} YTD {k:28s} {cu[k]:>8}   |  {Y-1} YTD {pr[k]}")
    q.append(f"  YoY change: {S['yoy']}")
    q.append("\nSPOT CHECKS - open each advisory at https://www.cisa.gov/news-events/ics-advisories/<id lower-case> and confirm vendor, CVE, severity")
    rng = np.random.default_rng(2026)
    sp = cur_p.dropna(subset=["cve_id"])
    picks = []
    picks += [("KEV in window", r) for _, r in sp[sp.known_exploited].head(2).iterrows()]
    picks += [("highest EPSS", sp.sort_values("epss", ascending=False).iloc[0])]
    picks += [("mega advisory", r) for _, r in sp[sp.mega_advisory].head(1).iterrows()]
    picks += [("ONG product line", r) for _, r in sp[sp.ong_product_class == "ong_product_line"].head(1).iterrows()]
    idx = rng.choice(len(sp), size=5, replace=False)
    picks += [("random (seed 2026)", sp.iloc[i]) for i in idx]
    for why, r in picks:
        q.append(f"  [{why}] {r['ICS-CERT_Number']} | {r['cve_id']} | {r['Vendor']} | {str(r['Product'])[:50]} | sev={r['CVSS_Severity']} | KEV={r['known_exploited']} | EPSS={r['epss']} | tier={r['priority_tier']}")
    q.append("\nKNOWN CAVEATS CARRIED INTO THE REPORT: see docs/LIMITATIONS.md")
    open(os.path.join(P, "qa_report.txt"), "w", encoding="utf-8").write("\n".join(q) + "\n")
    print("\n".join(q))


if __name__ == "__main__":
    main()
