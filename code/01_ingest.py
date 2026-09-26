#!/usr/bin/env python3
"""Step 1 - put the frozen input snapshot in data/raw/ and log its provenance.

The 2026 edition is built on one frozen, DOI-registered snapshot:
  ONG-OT Vulnerability Prioritization Dataset v1.1 (Zenodo, 10.5281/zenodo.22729882),
  itself a join of CISA ICS advisories (ICS Advisory Project mirror, ODbL v1.0),
  CISA KEV, FIRST EPSS, CISA Vulnrichment and MITRE ATT&CK for ICS, pulled 2026-09-12.

Usage:
  python code/01_ingest.py                      # download from the Zenodo record
  python code/01_ingest.py --from path/to/ong_ot_dataset_v1.1.csv   # use a local copy

Either way the SHA-256 is written to data/raw/PROVENANCE.txt and compared against
the value recorded in the upstream dataset's own provenance, so a stranger can tell
whether they are analysing the same bytes.
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
TARGET = os.path.join(RAW, "ong_ot_dataset_v1.1.csv")
ZENODO_RECORD = "22729882"
ZENODO_API = f"https://zenodo.org/api/records/{ZENODO_RECORD}"
DOI = "10.5281/zenodo.22729882"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download():
    with urllib.request.urlopen(ZENODO_API, timeout=60) as r:
        rec = json.load(r)
    files = rec.get("files", [])
    hit = [f for f in files if f.get("key", "").endswith("ong_ot_dataset_v1.1.csv")]
    if not hit:
        # the CSV may sit inside the release archive
        zips = [f for f in files if f.get("key", "").endswith(".zip")]
        if not zips:
            sys.exit("Zenodo record has no ong_ot_dataset_v1.1.csv or archive; download it by hand from https://doi.org/" + DOI)
        import io, zipfile
        url = zips[0]["links"]["self"]
        with urllib.request.urlopen(url, timeout=600) as r:
            z = zipfile.ZipFile(io.BytesIO(r.read()))
        name = [n for n in z.namelist() if n.endswith("data/processed/ong_ot_dataset_v1.1.csv")][0]
        with z.open(name) as src, open(TARGET, "wb") as dst:
            shutil.copyfileobj(src, dst)
        return url + "!" + name
    url = hit[0]["links"]["self"]
    with urllib.request.urlopen(url, timeout=600) as r, open(TARGET, "wb") as dst:
        shutil.copyfileobj(r, dst)
    return url


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src", help="local copy of ong_ot_dataset_v1.1.csv")
    a = ap.parse_args()
    os.makedirs(RAW, exist_ok=True)
    if a.src:
        shutil.copyfile(a.src, TARGET)
        source = f"https://doi.org/{DOI} (local copy of the published file: {os.path.basename(a.src)})"
    else:
        source = download()
    digest = sha256(TARGET)
    line = " | ".join([
        datetime.date.today().isoformat(),
        os.path.basename(TARGET),
        f"{os.path.getsize(TARGET)} bytes",
        f"sha256:{digest}",
        source,
        "frozen input snapshot for the 2026 edition",
    ])
    with open(os.path.join(RAW, "PROVENANCE.txt"), "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line)


if __name__ == "__main__":
    main()
