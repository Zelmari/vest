#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_HOME="${ROOT}/examples/.vest-demo"
REPORT_DIR="${ROOT}/examples/reports/generated"
TARGET="${ROOT}/examples/fixtures/demo-secret.txt"

mkdir -p "${DEMO_HOME}" "${REPORT_DIR}"

echo "Running VEST demo scan..."
VEST_HOME="${DEMO_HOME}" cargo run -p vest-cli -- scan "${TARGET}" \
  --target-type file \
  --scanner files \
  --provider none \
  --format terminal

SCAN_ID="$(VEST_HOME="${DEMO_HOME}" cargo run -q -p vest-cli -- scans list | awk 'NR==3 {print $1}')"

if [[ -z "${SCAN_ID}" || "${SCAN_ID}" == "Total:" ]]; then
  echo "Could not determine scan id from demo database" >&2
  exit 1
fi

echo
echo "Stored scans:"
VEST_HOME="${DEMO_HOME}" cargo run -q -p vest-cli -- scans list

echo
echo "Generating reports..."
VEST_HOME="${DEMO_HOME}" cargo run -q -p vest-cli -- report generate "${SCAN_ID}" \
  --format json \
  --output "${REPORT_DIR}/demo-report.json"
VEST_HOME="${DEMO_HOME}" cargo run -q -p vest-cli -- report generate "${SCAN_ID}" \
  --format markdown \
  --output "${REPORT_DIR}/demo-report.md"

echo
echo "Reports written to ${REPORT_DIR}"
