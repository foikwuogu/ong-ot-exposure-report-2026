#!/usr/bin/env python3
"""Step 2 - deduplicate, scope and derive the analytic tables.

Reads  data/raw/ong_ot_dataset_v1.1.csv and config/scope.json
Writes data/processed/cve_advisory_pairs.csv  (one row per unique CVE-advisory pair, all advisories, with scope flags)
       data/processed/advisories.csv          (one row per advisory, advisory-level fields)
       data/processed/build_log.json          (row counts at every stage, read by 03)
"""
import ast
import json
import os
import re

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw", "ong_ot_dataset_v1.1.csv")
OUT = os.path.join(ROOT, "data", "processed")
CFG = json.load(open(os.path.join(ROOT, "config", "scope.json"), encoding="utf-8"))


def ssvc_exploitation(s):
    if not isinstance(s, str) or not s.strip():
        return ""
    try:
        for d in ast.literal_eval(s):
            if "Exploitation" in d:
                return str(d["Exploitation"]).strip().lower()
    except (ValueError, SyntaxError):
        m = re.search(r"Exploitation'?:\s*'?(\w+)", s)
        return m.group(1).lower() if m else ""
    return ""


def cwe_list(s):
    if not isinstance(s, str):
        return []
    return sorted(set(re.findall(r"CWE-\d+", s)), key=lambda c: int(c.split("-")[1]))


def main():
    os.makedirs(OUT, exist_ok=True)
    log = {}
    d = pd.read_csv(RAW, low_memory=False)
    log["input_rows"] = int(len(d))
    log["input_rows_by_file_type"] = {
        "master": int(d["__source_file"].str.contains(CFG["dedup"]["keep_source_file_pattern"]).sum()),
        "per_year": int((~d["__source_file"].str.contains(CFG["dedup"]["keep_source_file_pattern"])).sum()),
    }

    # --- dedup -------------------------------------------------------------
    key = CFG["dedup"]["key"]
    log["unique_pairs_in_input"] = int(d.drop_duplicates(key).shape[0])
    m = d[d["__source_file"].str.contains(CFG["dedup"]["keep_source_file_pattern"])].copy()
    log["master_rows"] = int(len(m))
    # advisory-level scope evidence is collected from ALL master rows before the
    # within-file de-duplication, so dropping a repeated pair cannot drop a product
    # line that put the advisory in scope
    sc = CFG["scope"]
    _sec = m["Critical_Infrastructure_Sector"].fillna("").str.contains(sc["sector_regex"], case=False, regex=True)
    _cls = m["ong_product_class"].fillna("unmapped").ne("unmapped") if sc["include_mapped_ong_product_classes"] else pd.Series(False, index=m.index)
    _us = m["Product_Distribution"].fillna("").str.contains(sc["us_distribution_regex"], case=False, regex=True)
    ADV_SECTOR = set(m.loc[_sec, "ICS-CERT_Number"]); ADV_CLASS = set(m.loc[_cls, "ICS-CERT_Number"]); ADV_US = set(m.loc[_us, "ICS-CERT_Number"])
    log["within_master_duplicate_pairs_dropped"] = int(m.duplicated(key).sum())
    m = m.drop_duplicates(key, keep="first")
    log["rows_after_dedup"] = int(len(m))
    log["rows_without_cve_id"] = int(m["cve_id"].isna().sum())

    # --- dates -------------------------------------------------------------
    m["release_date"] = pd.to_datetime(m["Original_Release_Date"], format="%m/%d/%Y", errors="coerce")
    log["unparseable_release_dates"] = int(m["release_date"].isna().sum())
    m["release_year"] = m["release_date"].dt.year
    md = m["release_date"].dt.strftime("%m-%d")
    w = CFG["windows"]
    m["in_ytd_window"] = (md >= w["ytd_start_month_day"]) & (md <= w["ytd_end_month_day"])
    log["max_release_date"] = str(m["release_date"].max().date())

    # --- scope -------------------------------------------------------------
    # scope is an advisory property: an advisory is in scope if ANY of its rows qualifies
    a = m["ICS-CERT_Number"]
    m["scope_sector_energy"] = a.isin(ADV_SECTOR)
    m["scope_ong_class"] = a.isin(ADV_CLASS)
    m["scope_us_distribution"] = a.isin(ADV_US)
    rx = sc.get("exclude_regex")
    if rx:
        exc = m["ICS-CERT_Advisory_Title"].fillna("").str.contains(rx, case=False, regex=True) | m["Vendor"].fillna("").str.contains(rx, case=False, regex=True)
        ADV_EXCL = set(m.loc[exc, "ICS-CERT_Number"])
    else:
        ADV_EXCL = set()
    m["scope_excluded_non_ong"] = a.isin(ADV_EXCL)
    m["in_scope"] = (m["scope_sector_energy"] | m["scope_ong_class"]) & m["scope_us_distribution"] & ~m["scope_excluded_non_ong"]
    m["advisory_type"] = m["ICS-CERT_Number"].str.extract(r"^(ICS[A-Z]*)")[0].fillna("other")

    # --- CVE-level derived fields -------------------------------------------
    m["known_exploited"] = m["known_exploited"].astype(str).str.lower().eq("true")
    m["no_patch_available"] = m["no_patch_available"].astype(str).str.lower().eq("true")
    m["ssvc_exploitation"] = m["vulnrichment_ssvc"].map(ssvc_exploitation)
    pt = CFG["priority_tiers"]
    exploit_ev = m["ssvc_exploitation"].isin(["active", "poc"]) | (m["percentile"].fillna(0) >= pt["tier2_epss_percentile"])
    crit = m["CVSS_Severity"].fillna("").str.lower().eq("critical")
    m["priority_tier"] = 4
    m.loc[crit, "priority_tier"] = 3
    m.loc[exploit_ev, "priority_tier"] = 2
    m.loc[m["known_exploited"], "priority_tier"] = 1

    # --- advisory table -----------------------------------------------------
    m["cwes"] = m["CWE_Number"].map(cwe_list)
    g = m.groupby("ICS-CERT_Number")
    adv = pd.DataFrame({
        "release_date": g["release_date"].first(),
        "release_year": g["release_year"].first(),
        "in_ytd_window": g["in_ytd_window"].first(),
        "advisory_type": g["advisory_type"].first(),
        "vendor": g["Vendor"].first(),
        "title": g["ICS-CERT_Advisory_Title"].first(),
        "cvss_severity": g["CVSS_Severity"].first(),
        "cumulative_cvss": g["Cumulative_CVSS"].first(),
        "n_cves": g["cve_id"].nunique(),
        "any_kev": g["known_exploited"].any(),
        "max_epss": g["epss"].max(),
        "cwes": g["cwes"].first().map(lambda l: ";".join(l)),
        "n_cwes": g["cwes"].first().map(len),
        "sector": g["Critical_Infrastructure_Sector"].first(),
        "hq_country": g["Company_Headquarters"].first(),
        "in_scope": g["in_scope"].first(),
        "scope_sector_energy": g["scope_sector_energy"].any(),
        "scope_ong_class": g["scope_ong_class"].any(),
        "scope_excluded_non_ong": g["scope_excluded_non_ong"].any(),
    }).reset_index()
    adv["mega_advisory"] = adv["n_cves"] > CFG["mega_advisory_cve_threshold"]
    m = m.merge(adv[["ICS-CERT_Number", "mega_advisory"]], on="ICS-CERT_Number", how="left")

    keep = ["ICS-CERT_Number", "cve_id", "release_date", "release_year", "in_ytd_window", "advisory_type",
            "Vendor", "Product", "CVSS_Severity", "Cumulative_CVSS", "CWE_Number", "Critical_Infrastructure_Sector",
            "Product_Distribution", "Company_Headquarters", "known_exploited", "epss", "percentile",
            "ssvc_exploitation", "vulnrichment_remediation_text_present", "no_patch_available", "no_patch_basis",
            "ong_product_class", "cpg2_applicable_controls", "attack_ics_matched_entity",
            "scope_sector_energy", "scope_ong_class", "scope_us_distribution", "scope_excluded_non_ong", "in_scope", "mega_advisory",
            "priority_tier"]
    m[keep].to_csv(os.path.join(OUT, "cve_advisory_pairs.csv"), index=False)
    adv.to_csv(os.path.join(OUT, "advisories.csv"), index=False)

    log["advisories_total"] = int(len(adv))
    log["advisories_in_scope"] = int(adv["in_scope"].sum())
    log["pairs_in_scope"] = int(m["in_scope"].sum())
    log["scope_components_advisories"] = {
        "sector_energy_or_oilgas": int(adv["scope_sector_energy"].sum()),
        "ong_class_mapped": int(adv["scope_ong_class"].sum()),
        "both": int((adv["scope_sector_energy"] & adv["scope_ong_class"]).sum()),
        "excluded_for_non_us_distribution": int(((adv["scope_sector_energy"] | adv["scope_ong_class"]) & ~adv["in_scope"] & ~adv["scope_excluded_non_ong"]).sum()),
        "excluded_non_ong_energy_ev_charging": int(((adv["scope_sector_energy"] | adv["scope_ong_class"]) & adv["scope_excluded_non_ong"]).sum()),
        "excluded_non_ong_energy_ev_charging_edition_year_ytd": int(((adv["scope_sector_energy"] | adv["scope_ong_class"]) & adv["scope_excluded_non_ong"] & (adv["release_year"] == CFG["windows"]["edition_year"]) & adv["in_ytd_window"]).sum()),
    }
    json.dump(log, open(os.path.join(OUT, "build_log.json"), "w"), indent=2)
    print(json.dumps(log, indent=2))


if __name__ == "__main__":
    main()
