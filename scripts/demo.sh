#!/bin/sh
# Offline demo. Run from the repository root after `go build -o verdict ./cmd/verdict`.
set -eu
cd "$(dirname "$0")/.."
if [ ! -x ./verdict ]; then
  echo "build ./verdict first" >&2
  exit 1
fi
./verdict pack lint packs/draft/*.yaml packs/synthetic/*.yaml
./verdict pack test packs/draft/*.yaml packs/synthetic/*.yaml

run() {
  name="$1"
  pack="$2"
  snap="$3"
  ./verdict drill \
    --pack "$pack" \
    --snapshot "$snap" \
    --policy examples/policy/lab-zones.json \
    --author "Uddeshya Kumar" \
    --out "/tmp/${name}-report.json" \
    --openvex "/tmp/${name}.openvex.json"
  ./verdict openvex validate "/tmp/${name}.openvex.json"
  cmp "testdata/golden/${name}-report.json" "/tmp/${name}-report.json"
  cmp "testdata/golden/${name}.openvex.json" "/tmp/${name}.openvex.json"
}

run regresshion packs/draft/ecp-cve-2024-6387-openssh.yaml examples/snapshots/regresshion-lab.json
run log4shell packs/draft/ecp-cve-2021-44228-log4j.yaml examples/snapshots/log4shell-lab.json
run synthetic-polarity packs/synthetic/ecp-synthetic-polarity.yaml examples/snapshots/synthetic-polarity.json
run synthetic-mixed packs/synthetic/ecp-synthetic-mixed.yaml examples/snapshots/synthetic-mixed.json
echo "demo ok"
