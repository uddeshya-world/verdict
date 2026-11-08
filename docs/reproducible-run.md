# Reproducible offline run

The commands below do not contact a network. They use the snapshots committed in this repository. Evaluation time is the timestamp inside each snapshot (`2026-11-08T12:00:00Z`), not the time you happen to run the command.

```bash
go build -o verdict ./cmd/verdict

./verdict drill \
  --pack packs/draft/ecp-cve-2024-6387-openssh.yaml \
  --snapshot examples/snapshots/regresshion-lab.json \
  --author "Uddeshya Kumar" \
  --out /tmp/regresshion-report.json \
  --openvex /tmp/regresshion.openvex.json

./verdict openvex validate /tmp/regresshion.openvex.json
```

Byte comparison against the committed golden, after a build:

```bash
cmp testdata/golden/regresshion-report.json /tmp/regresshion-report.json
cmp testdata/golden/regresshion.openvex.json /tmp/regresshion.openvex.json
```

Repeat with:

| Pack | Snapshot | Golden prefix |
| --- | --- | --- |
| `packs/draft/ecp-cve-2021-44228-log4j.yaml` | `examples/snapshots/log4shell-lab.json` | `testdata/golden/log4shell` |
| `packs/synthetic/ecp-synthetic-polarity.yaml` | `examples/snapshots/synthetic-polarity.json` | `testdata/golden/synthetic-polarity` |
| `packs/synthetic/ecp-synthetic-mixed.yaml` | `examples/snapshots/synthetic-mixed.json` | `testdata/golden/synthetic-mixed` |

`scripts/demo.sh` runs the same commands and `cmp`s the goldens.

What "reproducible" means here: same pack bytes, same snapshot bytes, same author string, same Go `encoding/json` rules. It does not mean a reproducible-build attestation. Builds are not signed and no SLSA provenance is generated.

Changing `--author` changes the OpenVEX document and not the verdict states. `--author` is an operator-supplied label. The CLI does not authenticate it.

Overriding time on purpose, to show the clock is an input:

```bash
./verdict drill \
  --pack packs/draft/ecp-cve-2024-6387-openssh.yaml \
  --snapshot examples/snapshots/regresshion-lab.json \
  --evaluation-time 2026-12-01T00:00:00Z \
  --author "Uddeshya Kumar" \
  --out /tmp/regresshion-later.json
```

Facts observed at `2026-11-08T11:00:00Z` fall outside the pack's 24h `evidence_max_age` relative to 1 December, so assets that were determinate in the original demo become `needs_review` with a stale-evidence hint. That file is not a golden.
