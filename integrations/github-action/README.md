# Verdict diff GitHub Action

A composite action that gates a pull request on exploitability: it drills one condition pack against the base and the head snapshot and fails when `verdict diff` reports a regression (an asset moved into `exploitable`, or out of `not_affected`). The contract for `verdict diff` (classes, `--fail-on`, JSON shape, exit codes) is in [docs/agents.md](../../docs/agents.md#verdict-diff-and-the-pr-gate).

It uses no third-party actions. Steps:

1. Download `verdict_<ver>_linux_amd64.tar.gz` and `SHA256SUMS` from the GitHub release for `version`.
2. Take the archive's single line from `SHA256SUMS` and check it with `sha256sum -c`; when `sha256` is set, the archive must also match it.
3. `verdict drill` the pack against `before-snapshot` and `after-snapshot` (or take `before-report` and `after-report`).
4. `verdict diff --fail-on <fail-on>`, write the text diff to `$GITHUB_STEP_SUMMARY`, and exit with the diff's exit code: 0 pass, 3 `--fail-on` matched, 2 invalid input or reports for different packs or CVEs.

Runs on `ubuntu-*` (linux/amd64) runners. Needs a release that has `verdict diff` (v0.2.0 or later). Nothing is sent anywhere after the download.

## Inputs

| Input | Required | Default | Meaning |
| --- | --- | --- | --- |
| `version` | yes | | Release tag, e.g. `v0.2.0` |
| `sha256` | no | | Expected SHA-256 of the linux/amd64 archive. Pin it: `SHA256SUMS` comes from the same release as the archive, so on its own it only catches a corrupt download |
| `repository` | no | `uddeshya-world/verdict` | Repository that publishes the release |
| `pack` | with snapshots | | Condition pack YAML |
| `policy` | no | | Site zone policy JSON; without it exposure stays unknown |
| `before-snapshot`, `after-snapshot` | with `pack` | | Snapshots for the base and head side |
| `before-report`, `after-report` | instead of the three above | | Existing drill reports |
| `fail-on` | no | `regression` | `regression`, `any-affected-change`, or `any` |

Outputs: `exit-code`, `diff-json` (path of the `--json` result), `verdict-path` (the verified binary, for later steps).

## Example: a repository that keeps snapshots

The repository keeps a snapshot next to its manifests, regenerated whenever they change. For Kubernetes, render the manifests and import the kubectl-style JSON the importer reads (`verdict import k8s --help`), with a fixed evaluation time so the file only changes when the inputs do:

```bash
verdict import k8s --input rendered/cluster.json --cluster prod \
  --kb-version 2026.11 --evaluation-time 2026-11-01T00:00:00Z \
  --untrusted-zone-for-loadbalancer internet --untrusted-zone-for-ingress internet \
  --out verdict/snapshot.json
```

The workflow diffs the base branch's snapshot against the PR's:

```yaml
name: exploitability gate
on:
  pull_request:
    paths: ["deploy/**", "verdict/**"]
permissions:
  contents: read
jobs:
  verdict:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: base snapshot
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: git show "$BASE_SHA:verdict/snapshot.json" > "$RUNNER_TEMP/before.json"
      - uses: uddeshya-world/verdict/integrations/github-action@<full commit SHA> # v0.2.0
        with:
          version: v0.2.0
          sha256: <sha256 of verdict_0.2.0_linux_amd64.tar.gz from the release>
          pack: verdict/packs/ecp-cve-2025-1974-ingress-nginx.yaml
          policy: verdict/zones.json
          before-snapshot: ${{ runner.temp }}/before.json
          after-snapshot: verdict/snapshot.json
          fail-on: regression
```

Pin the action by full commit SHA, as for any other action. To gate several CVEs, repeat the step once per pack.

## What the gate does not prove

- Reports are caller-asserted. A PR that edits the snapshot it is judged on can drop an asset or change a fact. Regenerate snapshots in CI from the manifests where you can, review snapshot diffs like code, and use `fail-on: any` when a removed asset must fail the gate (removed assets are listed, never counted as an improvement).
- A different pack hash, pack status, policy, knowledge version, or evaluation time between the two sides is listed under `context` in the summary, not refused. Verdicts may have moved for that reason, not because of the PR.
- Exit 0 means no regression under the chosen `fail-on`, not that the head is safe. Read `needs_review` assets in the head report.

See threat model row A43 in [docs/threat-model.md](../../docs/threat-model.md).
