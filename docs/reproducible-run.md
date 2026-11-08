# Reproducible offline run

The commands below do not contact a network. They use the snapshots committed in this repository. Evaluation time is the timestamp inside each snapshot (`2026-11-08T12:00:00Z`), not the time you happen to run the command.

```bash
go build -o verdict ./cmd/verdict

./verdict drill \
  --pack packs/draft/ecp-cve-2024-6387-openssh.yaml \
  --snapshot examples/snapshots/regresshion-lab.json \
  --policy examples/policy/lab-zones.json \
  --author "Uddeshya Kumar" \
  --out /tmp/regresshion-report.json \
  --openvex /tmp/regresshion.openvex.json

./verdict openvex validate /tmp/regresshion.openvex.json
```

`openvex validate` does not look up `schemas/openvex.schema.json` relative to the current directory. The schema is embedded. `--schema` still accepts a path when you want to check a document against a different file.

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
| `packs/draft/ecp-cve-2022-22965-spring.yaml` | `examples/snapshots/spring4shell-lab.json` | `testdata/golden/spring4shell` |
| `packs/draft/ecp-cve-2024-3094-xz.yaml` | `examples/snapshots/xz-lab.json` | `testdata/golden/xz` |
| `packs/draft/ecp-cve-2025-1974-ingress-nginx.yaml` | `examples/snapshots/ingress-nginx-lab.json` | `testdata/golden/ingress-nginx` |

`scripts/demo.sh` runs the same commands and `cmp`s the goldens.

An import does not use the clock or the network. The evaluation time is the flag. `--complete` is rejected when any component is skipped, so a missing package URL cannot be reported later as `component_not_present`.

Import stores a canonical package URL: percent-escapes are decoded and qualifiers are sorted. Qualifiers are kept, including `arch` and `epoch`, so an advisory that omits them does not match. `verdict snapshot merge` concatenates snapshot files that share `kb_version` and `evaluation_time`. Duplicate asset ids are rejected.

```bash
./verdict import cyclonedx \
  --input examples/import/cyclonedx-openssh.json \
  --out /tmp/imported-snapshot.json \
  --asset-id bastion-01 \
  --asset-name bastion \
  --kb-version demo-2026.11.08 \
  --evaluation-time 2026-11-08T12:00:00Z
```

What "reproducible" means here: same pack bytes, same snapshot bytes, same author string, same Go `encoding/json` rules. It does not mean a reproducible-build attestation. Builds are not signed and no SLSA provenance is generated.

Changing `--author` changes the OpenVEX document and not the verdict states. `--author` is an operator-supplied label. The CLI does not authenticate it.

Overriding time on purpose, to show the clock is an input:

```bash
./verdict drill \
  --pack packs/draft/ecp-cve-2024-6387-openssh.yaml \
  --snapshot examples/snapshots/regresshion-lab.json \
  --policy examples/policy/lab-zones.json \
  --evaluation-time 2026-12-01T00:00:00Z \
  --author "Uddeshya Kumar" \
  --out /tmp/regresshion-later.json
```

Facts observed at `2026-11-08T11:00:00Z` fall outside the pack's 24h `evidence_max_age` relative to 1 December, so assets that were determinate in the original demo become `needs_review` with a stale-evidence hint. That file is not a golden.
