#!/usr/bin/env bash
# Rebuild the whole report from the frozen snapshot. Pass --final only after the verification gate.
set -euo pipefail
cd "$(dirname "$0")"
FINAL="${1:-}"
[ -f data/raw/ong_ot_dataset_v1.1.csv ] || python code/01_ingest.py
python code/02_build.py
python code/03_stats_qa.py
python code/04_figures.py $FINAL
node code/05_report.js $FINAL
if command -v soffice >/dev/null; then (cd report && soffice --headless --convert-to pdf ONG_OT_Exposure_Report_2026*.docx >/dev/null); fi
echo "Done. Read data/processed/qa_report.txt first."
