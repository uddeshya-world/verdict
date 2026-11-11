# Design plan (unvalidated input)

**Status:** This file is the design input that the repository was asked to implement from. It is **not** an audited market report, **not** a compliance attestation, and **not** an endorsement of the statistics, legal interpretations, vendor comparisons, or timelines it contains.

**Plan author:** Uddeshya Kumar

**Plan date:** 2026-11-08

**Placed in this repository:** 2026-11-08

External numbers, dates, and product comparisons below were **not** re-verified by the code in this repository. Several figures in the plan conflict with each other or are explicitly marked there as unverified. Do not quote them from this repository as established facts.

Where the implemented engine disagrees with a shorthand in this plan, the ADRs and the tests win. In particular, `not_affected` is not "any false leaf": the engine requires a reviewed pack and a logically sufficient proof that accounts for negation and for every branch of a disjunction. See `docs/adr/0002-not-affected-proof.md`.

The original plan text follows, unchanged.

---

Design plan v1 · Pre-code · Apache-2.0 intent

# Verdict: am I actually exploitable?

An open-source, air-gap-capable tool that checks a new critical CVE against the exploit preconditions in your own environment and returns an evidence-backed verdict per asset, exported as standard VEX.

Author: Uddeshya KumarUpdated: 2026-11-08Audience: coding agents and contributors

EXPLOITABLEVULNERABLE, NOT EXPOSEDNOT AFFECTEDNEEDS REVIEW

Sections

1. [0Executive summary](#0-executive-summary)
2. [1Problem validation — is this real?](#1-problem-validation-is-this-real)
3. [2Users (think from their seat, not ours)](#2-users-think-from-their-seat-not-ours)
4. [3Success criteria (from the AppSec engineer's seat)](#3-success-criteria-from-the-appsec-engineers-seat)
5. [4Product scope](#4-product-scope)
6. [5Core concepts & data model](#5-core-concepts-data-model)
7. [6System architecture](#6-system-architecture)
8. [7Sandbox / replica verification design](#7-sandbox-replica-verification-design)
9. [8Air-gapped operational model](#8-air-gapped-operational-model)
10. [9Hardest parts, failure modes, workarounds](#9-hardest-parts-failure-modes-workarounds)
11. [10Open-source strategy & end-to-end lifecycle](#10-open-source-strategy-end-to-end-lifecycle)
12. [11Build plan for the coding agent](#11-build-plan-for-the-coding-agent)
13. [12Recommended minimal viable scope (the one-paragraph answer)](#12-recommended-minimal-viable-scope-the-one-paragraph-answer)
14. [13Assumptions & confidence](#13-assumptions-confidence)
15. [14Open questions](#14-open-questions)
16. [·Sources](#sources)

## 0. Executive summary

**What it is:** an on-prem, air-gap-capable tool that takes a newly disclosed critical/high CVE and returns, for *each affected asset in your environment*, one of four evidence-backed verdicts:

| Verdict | Meaning | VEX mapping |
| --- | --- | --- |
| EXPLOITABLE | Vulnerable build + exploit preconditions met + reachable from an untrusted zone + no verified mitigation | `affected` |
| VULNERABLE, NOT EXPOSED | Preconditions met, but reachable only from trusted zones (still a lateral-movement risk) | `affected` (lower priority) |
| NOT AFFECTED | At least one required precondition is *positively proven false* with high-confidence evidence | `not_affected` + justification |
| NEEDS REVIEW | Evidence is missing/ambiguous. Tool lists exactly what's missing and how to resolve it | `under_investigation` |

**Why it matters:** scanners report "package X version Y present". AppSec teams then spend hours to days per critical CVE manually answering: *which hosts, is the vulnerable feature enabled, is it reachable, is there a control in the way?* Verdict automates that chain, emits standard VEX, and keeps an audit-grade evidence bundle — all without data leaving the network.

**Core insight / differentiator:** split the system into two halves: 1. **Pack Factory (connected, open-source community side):** turns prose advisories into machine-checkable **Exploitability Condition Packs (ECPs)** — the exploit preconditions for a CVE, plus test fixtures that prove each check works. Like Nuclei templates, but for *preconditions*, not attacks. 2. **Verdict Engine (air-gapped, deterministic):** evaluates ECPs against your inventory/config/network/controls using three-valued logic (true/false/unknown). No LLM and no network calls are needed at runtime.

The hard, scarce knowledge (what makes a CVE exploitable) is crowdsourced and signed once. The sensitive data (your environment) never leaves.

---

## 1. Problem validation — is this real?

**Verdict: Yes, and it's getting worse in 2026. But the "detect + prioritize" layer is crowded. The open gap is narrow and real: *per-environment precondition verification, with evidence, that works air-gapped.* Build for that gap and integrate with everything else.**

### 1.1 Evidence (facts, with sources)

| Signal | Data | Source (date) |
| --- | --- | --- |
| Very few CVEs get exploited | \~0.2–0.5% of CVEs ever land in CISA KEV; \~5–6% show up in broader EPSS-style exploitation data. H1 2026: 85 of 35,364 new CVEs (0.24%) in KEV | [Safeguard](https://safeguard.sh/resources/blog/what-share-of-vulnerabilities-actually-get-exploited), [Axis Intelligence, 2026-08](https://axis-intelligence.com/vulnerability-exploitation-statistics/), [Ayi NEDJIMI H1-2026 recap](https://ayinedjimi-consultants.fr/news/bilan-cve-h1-2026-35000-vulnerabilites), [Trend Micro 2026](https://www.trendmicro.com/en/research/26/g/making-sense-of-the-vulnpocalypse.html) |
| Volume keeps going up | \~35k CVEs in H1 2026 alone. VulnCheck: the ratio of new KEV entries to new CVEs fell to 1.4% in H1 2026, so the noise is growing faster than the signal | [opensourcesecurity.io on VulnCheck, 2026-08](https://opensourcesecurity.io/2026/2026-08-vulncheck-state-of-exploitation/) |
| NVD stopped enriching every CVE | 2026-04-15: NIST moved to risk-based enrichment. \~29k pre-March-2026 CVEs were reclassified "Not Scheduled". CPE/CVSS data for many CVEs will never arrive | [Help Net Security, 2026-04-16](https://helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment), [CSA research note, 2026-04-29](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/) |
| Time-to-exploit collapsed | Reported mean/median time from disclosure to working exploit is now hours, roughly 10h in 2026 (figures conflict between sources; verify against M-Trends 2026). Verizon DBIR 2026: median 43 days to fully fix a KEV vuln | [CSA CISO briefing, 2026-05-12](https://labs.cloudsecurityalliance.org/research-rb/ciso-daily-briefing-20260512/), [Aviatrix 2026](https://aviatrix.ai/threat-research-center/ai-assisted-exploit-development-outpaces-scanner-detection-2026) |
| Reachability cuts noise a lot | Vendors claim 60–92% fewer SCA findings with reachability (Endor 92%, Socket up to 80–90%). These are vendor numbers, and false-negative rates are not disclosed | [Endor Labs](https://www.endorlabs.com/lp/sca-with-reachability), [Socket docs](https://docs.socket.dev/docs/reachability-analysis), [Black Duck on FNs](https://www.blackduck.com/blog/vulnerability-reachability-in-sca.html) |
| Regulation now rewards "not exploitable *in my product*" with evidence | EU CRA reporting duties took effect 2026-09-11 (24h early warning for actively exploited vulns). A component vuln that is *not exploitable in the product* is not reportable, so you need evidence to prove that | [Jones Day, 2026-07](https://www.jonesday.com/en/insights/2026/07/eu-cyber-resilience-act-24hour-reporting-duties-start-september-11-2026), [EC CRA reporting](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) |

**Unverified / from prior knowledge (flagged, needs fresh confirmation):** DORA (EU banks, in force Jan 2025), NIS2, India CERT-In 6-hour incident reporting (2022 directions), RBI cyber resilience guidance, and FDA premarket SBOM requirements all push in the same direction: a fast, evidenced answer to "are we affected?".

### 1.2 Practitioner reality (my inference as a corporate AppSec engineer)

The real pain is the **fire drill**, not the backlog dashboard. A CVE trends on X at 09:00. By 12:00 the CISO wants "are we exposed, where, what are we doing". Today that answer is put together from: - scanner output (version match only, and often wrong on distro backports), - Slack threads with platform teams ("can you check if `formatMsgNoLookups` is set on these 40 services?"), - tribal knowledge about which systems face the internet. The answer arrives late, has no evidence attached, and is never recorded in a form an auditor or the next engineer can reuse.

### 1.3 Who already covers what (honest competitive map)

| Category | Examples | What they do well | Why they don't solve this |
| --- | --- | --- | --- |
| On-prem vuln scanners | Tenable Security Center / Nessus offline plugins, Qualys private cloud, Rapid7 on-prem | **Incumbent in air-gapped estates.** Version detection and some config checks via plugins | Mostly "vulnerable version present". Weak on code reachability, network path and compensating controls. No evidence-chained VEX. Plugin logic is closed |
| SCA + reachability | Endor Labs, Socket/Coana, Snyk, Semgrep Supply Chain, Black Duck | Function-level code reachability | Code-only (ignores runtime config, exposure, controls). Mostly SaaS. Air-gapped support is limited or enterprise-gated |
| CNAPP / attack path | Wiz, Orca, Prisma Cloud | Cloud graph, exposure, "toxic combinations" | SaaS. Cloud-first. Not usable in true air-gap or on-prem OT/brownfield |
| Runtime reachability | Oligo, Kodem, Sysdig "in-use" | Which libraries/functions are actually loaded | Runtime agent in prod (a hard sell in regulated/OT). SaaS backends |
| BAS / automated pentest | Pentera, Horizon3 NodeZero, SafeBreach | Proves exploitability by attacking | Runs exploits against production. Change-control nightmare. Generic, not per-CVE-precondition |
| OSS building blocks | Trivy, Grype, Syft, Dependency-Track, OpenVEX/vexctl, govulncheck, Nuclei, Batfish, DefectDojo | Detection, SBOM, VEX format, network config analysis | **No open tool ties CVE preconditions + environment evidence + VEX together.** BitVex (embedded/Yocto, offline) is the closest, but it is narrow |

**Gap Verdict fills:** an open, air-gapped, evidence-first precondition verifier that *consumes* scanner/SBOM output and *produces* standard VEX. **Don't rebuild the scanner.**

### 1.4 Critique of the original brief (what I changed and why)

1. **"Precision over recall" is ambiguous here.** There are two different errors: - A false **EXPLOITABLE** wastes effort and erodes trust (annoying). - A false **NOT AFFECTED** leaves a real hole open and is a breach/liability event (catastrophic).

Design rule: **`not_affected` requires positive evidence that a required precondition is false. Absence of evidence never produces `not_affected`, it produces NEEDS REVIEW.** For `affected`, version + precondition evidence is enough, and confidence is shown. 2. **"Not reachable from the internet" ≠ not affected.** Network isolation lowers priority but does not remove the vuln (insiders, lateral movement, flat OT networks). So it gets its own verdict (VULNERABLE, NOT EXPOSED), never `not_affected`. 3. **Sandbox replicas prove less than people think.** A replica shows that "this build + this config is exploitable". It cannot prove that prod is identical. So the design verifies *preconditions* first, uses the sandbox to confirm, and shows a **replica fidelity score**. 4. **"Determine exploitability for any CVE" is not achievable.** Precondition knowledge exists as prose for a few hundred CVEs a year that matter (KEV + criticals in common enterprise stacks). Scope to those. That's where the time pressure is anyway. 5. **LLMs do not belong in the air-gapped decision path.** Use them upstream (connected side) to *draft* packs that humans review. Optionally run a local model on-prem to draft packs for uncovered CVEs, but drafts can never produce `not_affected` until a human approves them.

---

## 2. Users (think from their seat, not ours)

### 2.1 Personas

| Persona | Context | What they need from Verdict | What makes them abandon it |
| --- | --- | --- | --- |
| **P1: AppSec / ProdSec engineer (primary)** | Bank, hospital, defense contractor, utility. 2–6 people covering thousands of assets. Owns the CVE response | A defensible answer per asset in \< 2h, a list of the 3 things to fix *today*, and a report they can forward | One wrong "not affected". Tool needs weeks of setup. Making them fill forms |
| **P2: Platform / SRE / sysadmin** | Owns the hosts, clusters and firewalls. Gets the "please check X" requests | To be asked less. Read-only collectors they can audit. Exact remediation steps | Agents in prod. Write access. Noisy tickets |
| **P3: CISO / risk owner** | Briefs the board/regulator | One screen: exposure count, trend, what's done, residual risk, sign-off | Jargon, no confidence levels, no audit trail |
| **P4: Auditor / regulator / internal audit** | Asks "why didn't you patch CVE-X in 72h?" | Immutable evidence bundle, timestamps, who decided | Screenshots and Slack threads |
| **P5: PSIRT at a product manufacturer (CRA)** | Ships software/devices to customers | Generate customer-facing VEX/CSAF per product release, with evidence | Can't separate internal data from published VEX |
| **P6: Pack contributor (community researcher)** | Security researcher, vendor PSIRT, P1s at other companies | Easy pack format, local test harness, credit | Heavy review bureaucracy, unclear schema |

### 2.2 Jobs to be done

1. **Fire drill** — "A critical CVE just dropped. Tell me where I'm actually exploitable, with proof, before the 12:00 call." *(The MVP lives or dies here.)*
2. **Backlog burn-down** — "I have 4,000 'critical' scanner findings. Close the ones that aren't exploitable *with evidence* so I can focus."
3. **Prove it later** — "Six months on, show the auditor why we marked CVE-X not affected, what we knew, and who signed it."
4. **Stay right over time** — "Tell me if a verdict flips: someone enabled the vulnerable feature, opened a port, or removed the WAF rule."
5. **Tell customers** (P5) — "Publish VEX for our product versions."

### 2.3 Primary user journey — the fire drill (narrative)

> 09:05 — A critical OpenSSH CVE is trending. The AppSec engineer opens Verdict (on-prem web UI) → **"New drill" → types the CVE ID.**
> 
> 09:06 — Verdict shows: *"Pack ECP-CVE-XXXX available (community-reviewed, signed, knowledge bundle dated 2026-11-07). Evaluating against 2,314 assets…"* If no pack is in the local bundle: *"No reviewed pack yet. Showing a version-only match (low confidence). Request an emergency pack import, or start a local draft."*
> 
> 09:08 — **The exposure funnel** (the hero screen): `2,314 assets in scope └─ 412 have openssh installed [SBOM + host collector] └─ 118 vulnerable build (distro-backport aware) [RHSA/USN/DSA feeds] └─ 97 sshd running & listening [host collector] └─ 31 no mitigation (LoginGraceTime≠0) [sshd_config read] ├─ 4 reachable from untrusted zone → EXPLOITABLE (P0) └─ 27 internal only → VULNERABLE, NOT EXPOSED (P2) NOT AFFECTED: 381 (each with justification + evidence) NEEDS REVIEW: 19 → "14: collector lacks read on /etc/ssh/sshd_config (grant sudo-less read or run pack-provided command); 5: network zone unknown (tag these assets)"` 09:15 — They click one of the 4 P0 assets: the evidence chain (package version from `rpm -q`, config line, listening socket, firewall rule permitting 0.0.0.0/0 → 22), each with source, timestamp and confidence. Remediation is pre-filled: patched package version, or the interim mitigation with its trade-off ("LoginGraceTime 0 → DoS exposure").
> 
> 09:20 — Optional **"Confirm in sandbox"** on one representative asset: Verdict builds a replica from the image digest + captured config (secrets stripped), runs the pack's safe probe, and attaches pcap + logs. *"Replica fidelity 94% (kernel version differs)."*
> 
> 09:30 — **"Create tickets"** → 4 P0 tickets to the owning teams in on-prem Jira/ServiceNow, each with exact host, fix and evidence link. **"Export"** → OpenVEX + PDF brief for the CISO.
> 
> 11:00 — Two hosts patched. Verdict re-collects automatically → funnel updates → drill shows "P0: 2 remaining".
> 
> Over the next weeks the drill stays open as a **watch**. If config drift reintroduces exposure, the verdict flips and an alert fires.

### 2.4 Other journeys (short)

- **Backlog burn-down:** import Trivy/Grype/Nessus findings → "Evaluate all with packs" → bulk view grouped by CVE → bulk-accept `not_affected` verdicts where confidence is High → export VEX to Dependency-Track so scanners stop re-alerting.
- **Audit:** search by CVE/asset/date → "Evidence bundle" → signed tarball (verdict, inputs, evidence, pack version, knowledge bundle version, approver) that verifies offline with `verdict evidence verify`.
- **PSIRT (P5):** define a *product* (set of SBOMs + build configs) → evaluate → publish CSAF VEX with only product-level facts (internal asset data stripped).

### 2.5 UX principles (non-negotiable product rules)

1. **Every verdict shows *why*, *how sure*, and *what would change it*.** No bare labels.
2. **Unknowns are first-class.** NEEDS REVIEW always comes with a concrete next action ("grant read on X", "tag zone", "run probe P1", "attest WAF rule").
3. **Show knowledge freshness everywhere:** "Knowledge as of 2026-11-07 (1 day old)". Stale knowledge (> 7 days) shows a banner.
4. **Coverage is shown as prominently as findings:** "You have collector coverage on 71% of assets". You can't be not affected on assets you can't see.
5. **Time to first value: \< 30 minutes** from offline installer to first drill (using SBOM import only).
6. **CLI parity:** everything in the UI is scriptable (`verdict drill CVE-…`), because P1s automate.
7. **Language is precise and legally careful:** "Not affected *based on evidence collected at T*", never "safe".

---

## 3. Success criteria (from the AppSec engineer's seat)

| Metric | Target (MVP → v1) | How measured |
| --- | --- | --- |
| Time from CVE (with pack available) to a defensible verdict across estate | \< 2h → \< 30 min | Drill timestamps |
| **False NOT AFFECTED rate** | **0 on benchmark**, \< 0.5% in field audits | `verdict-bench` ground truth + sampled manual review |
| Precision of EXPLOITABLE | ≥ 90% → ≥ 95% | Benchmark + user "disagree" feedback |
| Determinate verdict rate (not NEEDS REVIEW) on covered assets | ≥ 70% → ≥ 85% | Drill stats |
| Pack latency (KEV/trending critical → reviewed signed pack) | \< 72h → \< 24h | Pack repo metadata |
| Setup to first drill | \< 30 min (SBOM-only), \< 1 day (collectors) | Onboarding telemetry *opt-in, local only* |
| Platform-team asks avoided per drill | Qualitative → track | User interviews |

---

## 4. Product scope

### In scope (v1)

- Linux hosts, containers, Kubernetes, common middleware (web servers, JVM apps, SSH, OpenSSL, ingress controllers, CI tools, VPN/edge appliances via config import).
- CVE classes: RCE, auth bypass, SSRF, deserialization, path traversal, privilege escalation (local preconditions).
- Inputs from existing tools (SBOMs, scanner exports). Outputs as standard VEX.

### Explicitly out of scope (v1) — say so in docs

- Being a scanner (use Trivy/Grype/Nessus).
- Exploit chaining / full attack-path simulation (flagged as a limitation, roadmap).
- Windows estate depth (basic version checks via imports only; WinRM collector in v1.x).
- OT/ICS protocol-level verification (config/version only; never active probing of OT).
- Running exploits against production. **Never by default.**
- DoS-class verification by execution (preconditions only).

---

## 5. Core concepts & data model

### 5.1 Exploitability Condition Pack (ECP) — the heart of the system

One YAML document per CVE (or per CVE × component variant). It is versioned, signed, and ships with test fixtures.

```yaml
apiVersion: verdict.dev/v1
kind: ConditionPack
metadata:
  id: ECP-CVE-2024-6387-openssh
  cve: [CVE-2024-6387]
  title: "OpenSSH sshd signal-handler race (regreSSHion)"
  severity_context: "Unauthenticated RCE as root on glibc Linux; practical exploitation demonstrated on 32-bit, harder on 64-bit"
  status: reviewed            # draft | reviewed | deprecated
  confidence_ceiling: high    # max confidence any verdict from this pack may claim
  authors: [ ... ]
  reviewers: [ ... ]          # >= 2 for status=reviewed
  sources:                    # advisories this pack was derived from
    - https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt
    - vendor CSAF/OVAL refs …
  kb_min_version: 2026.11.01
component:
  purls: ["pkg:generic/openssh", "pkg:rpm/*/openssh-server", "pkg:deb/*/openssh-server"]
  affected:
    upstream: [">=8.5p1 <9.8p1", "<4.4p1"]
    distro_fixed_via: [rhsa, usn, dsa, alsa, suse]   # backport-aware: distro advisory overrides upstream range
conditions:                   # three-valued boolean tree
  all_of:
    - ref: C1_vulnerable_build
    - ref: C2_platform_glibc
    - ref: C3_sshd_running
    - not:
        ref: M1_logingracetime_zero      # mitigation present => condition false
checks:
  C1_vulnerable_build:
    type: package_version
    negation_justification: component_not_present | vulnerable_code_not_present
  C2_platform_glibc:
    type: host_fact
    fact: libc.family
    equals: glibc
    negation_justification: vulnerable_code_not_present
  C3_sshd_running:
    type: process_listening
    process: sshd
    negation_justification: vulnerable_code_not_in_execute_path
  M1_logingracetime_zero:
    type: config_value
    file: /etc/ssh/sshd_config
    parser: sshd_config            # includes Include directives + Match blocks
    key: LoginGraceTime
    equals: "0"
    tradeoff: "Removes RCE vector; makes sshd trivially DoS-able (MaxStartups exhaustion)"
    negation_justification: inline_mitigations_already_exist
exposure:                       # does NOT affect affected/not_affected; drives EXPLOITABLE vs NOT EXPOSED
  service: { port: 22, proto: tcp }
  untrusted_sources: [internet, partner, user_lan]   # mapped to customer zone labels
probes:                         # optional sandbox verification
  - id: P1_banner_and_timing
    class: fingerprint          # fingerprint | precondition_trigger | benign_canary
    destructive: false
    runner: builtin/ssh-banner
remediation:
  fix: "Upgrade to distro-fixed openssh (see advisory per distro) or upstream >= 9.8p1"
  interim: [M1_logingracetime_zero]
tests:                          # REQUIRED for status=reviewed; CI builds and runs these
  - fixture: fixtures/ubuntu-22.04-openssh-vuln/   # Dockerfile; expected: affected
    expect: affected
  - fixture: fixtures/ubuntu-22.04-openssh-fixed/
    expect: not_affected
    expect_justification: vulnerable_code_not_present
  - fixture: fixtures/vuln-with-lgt0/
    expect: not_affected
    expect_justification: inline_mitigations_already_exist
```

**Check types (MVP set):** `package_version` (distro-aware), `file_exists`, `file_hash`, `config_value` (pluggable parsers: ini, yaml, json, xml, properties, sshd_config, nginx, httpd, java system props/env), `env_var`, `process_running`, `process_listening`, `kernel_version`, `kernel_module_loaded`, `host_fact`, `k8s_resource` (JSONPath over manifests), `jar_class_present` (fat-jar aware, e.g. JndiLookup.class), `manual_attestation` (with expiry + owner). **Later:** `code_reachable` (govulncheck for Go first; others via pluggable analyzers), `runtime_loaded` (eBPF/proc maps snapshot), `network_path` (Batfish query), `waf_rule_present` (rule export parsers).

### 5.2 Three-valued evaluation semantics (Kleene logic) — must be exact

- Each check returns `TRUE | FALSE | UNKNOWN` + `confidence ∈ {confirmed, high, medium, low}` + `evidence[]`.
- `all_of`: FALSE if any FALSE; else UNKNOWN if any UNKNOWN; else TRUE. `any_of`: dual. `not`: swaps TRUE/FALSE, keeps UNKNOWN.
- **Verdict derivation per (asset, CVE):**
- Tree = TRUE → `affected`. Then the exposure check decides EXPLOITABLE (reachable from an untrusted zone, or zone UNKNOWN → treat as EXPLOITABLE and flag it) vs VULNERABLE, NOT EXPOSED. Confidence = min(leaf confidences, pack ceiling).
- Tree = FALSE → `not_affected` **only if** the falsifying leaf has confidence ≥ high **and** its evidence is *observed* (directly read), not inferred. Justification = that leaf's `negation_justification`. Otherwise → NEEDS REVIEW.
- Tree = UNKNOWN → NEEDS REVIEW + a list of UNKNOWN leaves, each with a `resolution_hint` (generated from check type: missing permission, missing collector, needs attestation, needs probe).
- Packs with `status: draft` can only produce `affected` or NEEDS REVIEW. They can never produce `not_affected`.
- **Determinism:** same inputs + same pack + same KB version → byte-identical verdict record. This is tested.

### 5.3 Environment model (stored locally)

```
Asset(id, kind[host|container|pod|image|appliance|app|k8s_workload], name, owner_team, zones[], criticality, labels)
Software(asset_id, purl, version, distro_release, source[sbom|collector|import], observed_at)
Fact(asset_id, key, value, source, observed_at)               # host facts, config values, processes
Exposure(asset_id, port, proto, reachable_from_zone, evidence_ref, method[k8s|lb|batfish|zone_label|manual])
Control(id, kind[waf|config|selinux|egress_block|manual], scope, attested_by, expires_at)
EvidenceBlob(sha256, media_type, bytes, collected_by, collected_at)   # content-addressed
Verdict(asset_id, cve, pack_id@version, kb_version, state, justification, confidence, leaf_results[], computed_at, superseded_by)
Decision(verdict_id, actor, action[accept|override|risk_accept], reason, expires_at)  # human sign-off layer
AuditLog(seq, prev_hash, actor, action, payload_hash, ts)     # hash-chained, append-only
```

Relational (SQLite for single-node, Postgres for team). **No graph DB.** Too much ops burden for air-gapped customers; recursive CTEs are enough.

---

## 6. System architecture

### 6.1 Components

```
                 CONNECTED SIDE (public / vendor / customer DMZ)            │        AIR-GAPPED SIDE (customer)
                                                                           │
 Advisories (CVE5, OSV, KEV, EPSS,     ┌──────────────────────────┐        │   ┌───────────────────────────────────────┐
 vendor CSAF/OVAL, distro feeds) ────▶ │ Pack Factory             │        │   │ verdict server (single Go binary)     │
                                       │  - feed mirror           │        │   │  ┌──────────┐ ┌──────────┐ ┌────────┐ │
 Community PRs (packs + fixtures) ───▶ │  - pack CI: schema lint, │        │   │  │ KB store │ │ Engine   │ │ Web UI │ │
                                       │    fixture build & test  │        │   │  │ (bundles)│ │ (3-val)  │ │ + API  │ │
 LLM-assisted drafting (optional) ───▶ │  - 2-reviewer approval   │        │   │  └──────────┘ └──────────┘ └────────┘ │
                                       │  - bundle builder        │        │   │  ┌──────────┐ ┌──────────┐ ┌────────┐ │
                                       │  - offline signing (HSM) │        │   │  │Collectors│ │ Sandbox  │ │Exporter│ │
                                       └───────────┬──────────────┘        │   │  │ (RO)     │ │ runner   │ │VEX/PDF │ │
                                                   │ signed OCI bundle     │   │  └──────────┘ └──────────┘ └────────┘ │
                                                   ▼                       │   └──────┬──────────┬──────────┬──────────┘
                                   internal mirror / USB / data diode ─────┼─────────▶│ import + verify sig     │
                                                                           │          ▼          ▼          ▼
                                                                           │   SSH/K8s/SBOM   isolated    Jira/SNOW/
                                                                           │   /scanner imp.  sandbox     Dep-Track (on-prem)
```

### 6.2 Component responsibilities

| Component | Responsibility | Tech choice (and why) |
| --- | --- | --- |
| **verdict server** | API, engine, scheduler, UI host | **Go**: single static binary, trivial to ship into air-gaps, cross-compiles, good concurrency. FIPS-capable builds via Go's FIPS 140-3 module for government customers |
| **Web UI** | Drill, funnel, evidence, approvals | TypeScript + React, built to static assets and embedded in the binary (`embed`). No CDN calls |
| **CLI** | Same binary, `verdict <cmd>` | Cobra |
| **KB store** | Imported knowledge bundles, versioned and immutable | Content-addressed dir + SQLite index |
| **Engine** | Pack evaluation, 3-valued logic, verdict records | Pure Go, no I/O in the core (collectors feed facts in). Property-tested |
| **Collectors** | Gather facts **read-only** | SSH (allowlisted commands, no shell metachar, optional sudo-less), K8s API (read-only ClusterRole provided), SBOM import (CycloneDX/SPDX), scanner import (Trivy, Grype, Nessus `.nessus`, Dependency-Track API), config upload (zip of `/etc` subset), firewall config import (v1.x via Batfish) |
| **Sandbox runner** | Replica build + probe execution + evidence capture | v0.2: rootless Podman/Docker with hardened profile. v1: Firecracker microVM or Kata (needed for kernel CVEs). See §7 |
| **Exporters** | OpenVEX, CycloneDX VEX, CSAF 2.0 VEX, PDF brief, JSON/SARIF, ticket push | Libraries: openvex/go-vex; CSAF schema validation |
| **Bundle tool** | `verdict bundle build/verify/import/diff` | OCI artifacts (oras-go) signed with cosign **keyed** signatures (no Rekor/Fulcio online dependency) |
| **Pack SDK** | `verdict pack lint/test/new` for contributors | Same binary. `pack test` builds the fixtures and asserts verdicts |
| **Local LLM assist (optional, v1.x)** | Draft packs for uncovered CVEs from advisory text in the bundle | OpenAI-compatible local endpoint (llama.cpp / vLLM / Ollama). Off by default. Drafts are `status: draft` only |

### 6.3 Data flow for one drill

1. `drill CVE-X` → resolve packs from the KB (by CVE, then by purl). Fallback: version-only match from OSV/distro data (NEEDS REVIEW, low confidence).
2. Scope assets: Software rows whose purl matches the pack component.
3. Freshness: for each asset, if the facts the pack needs are older than the policy (default 24h) or missing, trigger targeted collection (only the commands/files the pack declares; the collector shows the exact command list before running).
4. Evaluate → Verdict rows (supersede old ones) → funnel aggregation.
5. Optional sandbox probe → evidence attached → confidence may upgrade to `confirmed`.
6. Human decisions → Decision rows → exports/tickets.
7. Watch mode: re-evaluate on new facts, new pack version, new KB, or control expiry. A flip raises an alert (webhook/email/syslog — all on-prem).

### 6.4 Security of the tool itself (it's a crown-jewel map of your weaknesses)

- Verdict's database is literally a list of your exploitable systems. **Encrypt at rest** (SQLCipher / Postgres TDE), restrict access, and log every read of an EXPLOITABLE list.
- Collector credentials: stored in an OS keyring or an external vault (HashiCorp Vault / CyberArk on-prem), never in the DB in plaintext. Least privilege, with a provided sudoers snippet that only allows the declared read commands.
- AuthN: local accounts + LDAP/AD + OIDC (Keycloak/ADFS). RBAC roles: viewer, analyst, approver, admin, sandbox-operator.
- Packs are untrusted input until signature-verified against configured trust roots. The engine treats pack content as data. Checks are a closed set of typed primitives, **no arbitrary code in packs**. Probes run only inside the sandbox and are referenced by ID from a signed probe registry.
- Supply chain: reproducible builds, SBOM for Verdict itself, signed releases, SLSA L3 provenance target.
- Threat-model doc (`docs/threat-model.md`) is a Phase-1 deliverable. Map it to OWASP ASVS. If the LLM assist is enabled, map it to OWASP LLM Top 10 (LLM01 prompt injection via advisory text is a real risk → drafts never auto-approve).

---

## 7. Sandbox / replica verification design

### 7.1 When to use it

- To **confirm** an `affected` verdict when the fix is disruptive (emergency change needs proof).
- To **resolve** UNKNOWN leaves that are behavioral ("is the vulnerable endpoint actually enabled in this build?").
- **Never** as the only basis for `not_affected` on prod (the replica can differ). A failed probe → "not reproduced in replica", not "not affected", unless the pack says that probe is a reliable negative test *and* fidelity ≥ threshold.

### 7.2 Replica construction

| Input | Source | Fidelity weight |
| --- | --- | --- |
| Image digest / package set | Registry (internal Harbor/Artifactory) or SBOM-rebuilt base | High |
| Config files | Captured by collector (pack-declared paths only) | High |
| Secrets | **Never copied.** Replaced with synthetic values of the same format | n/a |
| Env vars / feature flags | Captured, secret-pattern redacted | Medium |
| Kernel version | VM sandbox can match it; container sandbox cannot | High for kernel CVEs |
| Upstream dependencies (DBs, auth) | Stubbed by pack-declared mocks | Low |
| Data | Never copied | n/a |

**Fidelity score** = weighted match of the above against the prod asset. It is shown next to every sandbox result. Below the threshold (default 80%), the result is advisory only.

### 7.3 Isolation boundaries (defense in depth)

1. **Dedicated sandbox host(s)** or node pool, separate from the Verdict server. Never shares a kernel with prod.
2. **Strong boundary:** Firecracker/Kata microVM (v1). Containers (rootless, seccomp default, no caps, read-only rootfs, no host mounts, cgroup limits) are acceptable only for userland CVEs in v0.2, and the UI says so.
3. **Network:** no route out. Per-run isolated bridge with only {target, probe, canary-sink}. DNS sinkhole resolves everything to the canary sink. Egress drop is enforced at the host firewall, not just in the container config. Full pcap.
4. **Time & resource caps:** wall-clock timeout, CPU/mem/disk/pids limits, auto-destroy, no persistence.
5. **Probe policy (OPA/Rego, shipped default):** - `fingerprint` → analyst can run. - `precondition_trigger` → analyst can run in sandbox. - `benign_canary` (proves code execution / SSRF via a marker or callback to the sink) → needs approver role + reason. **Two-person rule configurable.** - Destructive / DoS / persistence payloads → **not representable in the probe schema at all.** - Any probe against a **production** target → disabled by default. If enabled by an admin: `fingerprint` only, with a change-ticket ID field, rate-limited and logged.
6. **Kill switch:** `verdict sandbox halt` tears down all runs.

### 7.4 Evidence capture

Each run produces an **evidence bundle**: replica manifest (digests, config hashes, fidelity), probe ID + version, stdout/stderr, target logs, pcap, canary-sink hits, timestamps, and runner host identity. It is wrapped as an in-toto/DSSE attestation signed by the instance key and stored content-addressed. `verdict evidence verify <bundle>` works offline.

### 7.5 Honest limits

- Exploit reliability: a probe can fail on a vulnerable target (race conditions like regreSSHion take hours of attempts). Packs must declare `negative_result_meaning: inconclusive | reliable`.
- Many CVEs have no safe probe. That's fine: the precondition checks carry the verdict and the sandbox is optional.
- Writing probes is effort and a risk surface. Only reviewed probes from the signed registry run. Community probes need ≥ 2 reviewers plus a fixture test showing they're non-destructive.

---

## 8. Air-gapped operational model

### 8.1 Connectivity tiers (the customer picks one in setup; the UI and docs adapt)

| Tier | Description | Update path |
| --- | --- | --- |
| **T0: True air-gap** | No automated external connectivity (defense, classified, some OT) | Signed bundles via removable media or a one-way data diode, through the customer's cross-domain transfer process. Weekly cadence + emergency single-pack drops |
| **T1: Restricted** | Egress only via an approved proxy/mirror host | An internal mirror pulls bundles. Verdict pulls from the mirror. Daily |
| **T2: Private cloud / on-prem connected** | Can reach an internal registry that syncs externally | OCI registry sync (Harbor replication). Hourly possible |

Verdict itself **never makes outbound calls** in any tier. Updates are always pull-from-internal or manual import.

### 8.2 Knowledge bundle contents

| Content | Upstream | Notes |
| --- | --- | --- |
| CVE records | CVE List V5 (cvelistV5) | Primary since NVD enrichment is partial |
| OSV dump | osv.dev all-ecosystems export | Ecosystem version ranges |
| Distro advisories | RHSA/OVAL/CSAF, Ubuntu USN/OVAL, Debian DSA/tracker, Alpine secdb, SUSE CSAF | **Backport correctness is the #1 source of scanner false positives** |
| Vendor CSAF | Vendor CSAF trusted providers, CISA CSAF (ICS advisories) |  |
| KEV | CISA KEV JSON | Priority signal |
| EPSS | FIRST EPSS daily CSV | Priority signal only, never a verdict input |
| NVD | CVSS/CPE where available | Optional enrichment, marked as partial |
| Go vuln DB | vuln.go.dev export | For govulncheck offline |
| ECPs + probes + fixtures metadata | verdict-packs repo | Signed |
| Sandbox base images | Minimal distro bases | Separate, larger "images bundle", monthly |

**Bundle format:** OCI artifact (fits the Harbor/Artifactory/Nexus registries air-gapped orgs already run), layered for delta updates, `index.json` with a content manifest and per-source timestamps. **Signing:** cosign keyed signatures. Project root key offline in an HSM, with intermediate keys for CI. Customers can **add their own trust root and re-sign** after internal review (common in defense: "nothing enters unless our team signed it"). Policy: `trust: [project, org:acme]`, `require: all|any`. **Size targets:** full KB \< 2 GB, daily delta \< 50 MB, single emergency pack \< 1 MB (fits any transfer process). **Freshness:** each source has an `as_of`. UI banner thresholds are configurable. Drills record the KB version used, which keeps old verdicts reproducible.

### 8.3 Emergency path (the fire drill in T0)

CVE drops → community/maintainers publish a reviewed pack (target \< 24h for trending criticals) → customer downloads the \~KB-sized signed pack on a connected workstation → transfers it via the approved process → `verdict bundle import ecp-CVE-X.oci.tar` → drill. If no pack exists yet: version-only match + a local draft pack (manual or local-LLM-assisted), marked draft, producing only affected/NEEDS REVIEW.

### 8.4 Model updates (optional LLM assist)

Model weights ship as a separate signed OCI artifact. They are pinned per release and never auto-updated. The engine works fully without them. Document GPU/CPU requirements honestly (a 7–14B class model on CPU is slow but workable for drafting).

### 8.5 Upgrades of Verdict itself

Offline installer tarball: binary + UI + migrations + default policies + checksums + signature. `verdict upgrade --from file.tar` with automatic DB backup and rollback. Helm chart + docker-compose + systemd unit + RPM/DEB. STIG-friendly defaults (no root, SELinux policy module in v1).

---

## 9. Hardest parts, failure modes, workarounds

| # | Hard part | Why it's hard | Workaround / design response | Residual risk |
| --- | --- | --- | --- | --- |
| 1 | **Precondition knowledge at scale** | Advisories are prose. Each pack needs expertise + fixtures | Scope to KEV + criticals in the top \~300 enterprise components. Community model with credit. LLM-assisted drafting upstream with mandatory human review. Ingest vendor CSAF `product_status` and remediations. Pack bounty/leaderboard | Coverage lags for niche software → falls back to version match + NEEDS REVIEW |
| 2 | **Inventory completeness** | You can't verdict what you don't see. Shadow assets | Coverage metric up front. Import from CMDB, scanners, K8s, cloud APIs (private cloud). "Unseen assets" never count as not affected | False comfort if users ignore coverage |
| 3 | **Distro backports** | RHEL/Ubuntu patch without changing upstream version | Distro advisory feeds + package release parsing. Fixtures per distro | New/rare distros |
| 4 | **Config semantics** | Includes, Match blocks, defaults when a key is absent, env overrides, runtime flags | Typed parsers per format with *default-value tables* per version. "Key absent → default X for version Y" is pack data. Unknown parser → UNKNOWN | Exotic config management (templated at runtime) |
| 5 | **Network path in brownfield** | Firewall rule sprawl, NAT, overlays, ZTNA | MVP: zone labels + K8s Service/Ingress/NetworkPolicy + LB config. v1.x: Batfish (OSS, offline) on firewall/router configs. Unknown zone → treat as exposed | Long tail of network gear |
| 6 | **Code reachability** | Reflection, DI, dynamic languages → unsound | Use only where sound-ish (govulncheck for Go). Elsewhere it's a confidence *modifier*, never a sole `not_affected` basis, unless the pack marks the language/analyzer pair as reliable | Lower determinate rate for JVM/Python apps |
| 7 | **Replica drift** | Sandbox ≠ prod | Fidelity score. Precondition checks on prod are primary, sandbox is confirmatory | Overtrust of sandbox results |
| 8 | **Compensating controls rot** | Someone deletes a WAF rule | Attestations expire (default 30d). Machine-checked controls where possible. Watch mode flips verdicts | Manual attestations are only as good as the attester |
| 9 | **Chained exploits** | CVE A alone isn't exploitable, A+B is | Out of scope v1. Pack field `chain_hints` surfaces known chains as NEEDS REVIEW | Real gap, documented |
| 10 | **Liability / anchoring** | Users treat "not affected" as permanent truth | Verdicts carry `computed_at` + expiry. Human sign-off layer. Careful wording. Evidence bundle | Org process issue, not just tooling |
| 11 | **Pack poisoning** | A malicious pack marks a real vuln not_affected | Signed packs, 2-reviewer rule, fixture tests in CI that must include a positive (affected) case, customer re-signing, transparency log of pack changes in the repo | Insider at maintainer level → mitigated by customer trust roots |
| 12 | **Tool becomes target** | It holds the exploitable-systems list | §6.4 controls | Standard |
| 13 | **Adoption friction in regulated orgs** | Change boards, security review of the tool itself | Read-only collectors, published threat model, SBOM, no agents in v1, works with SBOM import alone | Long sales/approval cycles |

**Where existing tools fall short (summary):** scanners stop at version. SCA reachability stops at code. CNAPPs stop at cloud and require SaaS. BAS fires real exploits at prod. None of them emit an *evidence-chained, reproducible VEX* that works in a true air-gap. That combination is the wedge.

---

## 10. Open-source strategy & end-to-end lifecycle

### 10.1 Repos

- `verdict` — server/CLI/UI/engine/collectors (Apache-2.0).
- `verdict-packs` — ECPs, probes, fixtures (Apache-2.0). CI builds fixtures, runs `verdict pack test`, requires 2 approvals, then signs.
- `verdict-bench` — ground-truth benchmark lab: vulnerable/non-vulnerable/mitigated variants for every reviewed pack, plus "tricky" cases (backports, absent-key defaults, Include files). It is the public scoreboard for false NOT AFFECTED = 0.
- `verdict-bundles` (release pipeline) — builds and signs KB bundles on schedule.

### 10.2 Community model

- Pack contribution guide, `verdict pack new CVE-X` scaffolding, local `pack test` with Docker.
- Credit in pack metadata. Monthly "most impactful packs".
- Vendor PSIRTs invited to publish official packs for their products (the trust signal is the vendor's signing key as an extra trust root).

### 10.3 Sustainability (later, optional)

Open core stays complete for a single team. Paid options could be a pack SLA feed (guaranteed \< 12h for criticals), HA/multi-site, FIPS-validated builds, support. Do not gate safety features (signing, evidence, sandbox isolation) behind paid tiers.

### 10.4 Customer lifecycle (how an org actually adopts it)

1. **Discover** — sees a drill demo on a famous CVE (Log4Shell funnel) in README/GIF.
2. **Evaluate (day 0, 30 min)** — on a laptop/VM: offline installer → import sample KB → import their Trivy/Syft SBOMs → run drills on 3 known CVEs → see the funnel.
3. **Security review of the tool (week 1–4)** — they read the threat model, SBOM, collector command allowlist, sudoers snippet. We make this easy: `docs/security-review-pack/`.
4. **Pilot (month 1)** — one business unit. K8s + SSH collectors read-only. Weekly KB bundle via their transfer process. First real fire drill.
5. **Production (month 2+)** — LDAP/OIDC, Postgres, ticketing integration, VEX → Dependency-Track, watch mode, sandbox host.
6. **Expand** — PSIRT use (CRA VEX publication), internal pack authoring for in-house software.

---

## 11. Build plan for the coding agent

### 11.1 Non-negotiables (enforce in code + CI)

1. **No outbound network at runtime** except to configured internal targets (collectors, ticketing, internal registry). Enforce with: (a) a single `netpolicy` package wrapping all HTTP/dial, with an allowlist from config; (b) a lint rule (`forbidigo`/custom analyzer) banning `net/http` default client use outside it; (c) an integration test that runs the full drill in a network namespace with no route and asserts success.
2. **`not_affected` only from observed, ≥ high-confidence falsifying evidence and reviewed packs.** Property tests over random condition trees with UNKNOWN leaves assert this invariant.
3. **Deterministic engine:** golden-file tests. Same input → byte-identical output.
4. **Collectors are read-only:** SSH collector executes only commands from a compiled allowlist with argument validation. Unit-test that shell metacharacters are rejected.
5. **No arbitrary code in packs.** Typed check primitives only.
6. **No secrets in logs, DB plaintext, evidence or replicas.** Redaction tests with seeded fake secrets.
7. Small PRs, tests with every change, `golangci-lint` + `gosec` + `govulncheck` + `trivy fs` + `gitleaks` in CI.

### 11.2 Repo layout (`verdict`)

```
cmd/verdict/              # main, cobra commands
internal/engine/          # 3-valued eval, verdict derivation (pure, no I/O)
internal/pack/            # schema, loader, lint, signature verify
internal/kb/              # bundle import/verify/index, OSV/distro/KEV/EPSS readers
internal/version/         # purl, distro-aware version comparison (rpm, dpkg, apk, semver, maven)
internal/collect/{ssh,k8s,sbom,importers}/
internal/parse/{sshd,nginx,ini,yaml,properties,jar}/
internal/store/           # sqlite/postgres, migrations, audit hash-chain
internal/evidence/        # content-addressed blobs, DSSE attestations
internal/sandbox/         # runner interface; podman impl; firecracker impl (later)
internal/export/{openvex,cdxvex,csaf,pdf,tickets}/
internal/api/             # REST + OpenAPI spec
internal/netpolicy/       # the ONLY place allowed to dial
web/                      # React UI, built into internal/api/static via embed
schemas/                  # JSON Schema for ECP, bundle manifest, evidence
docs/                     # architecture, threat-model, ADRs, security-review-pack
test/e2e/                 # docker-compose lab: hosts + k8s (kind) + fixtures
```

### 11.3 Phases & milestones

**Phase 0: Validate (1–2 weeks, before heavy code)** - \[ \] Interview 8–10 AppSec/platform engineers in regulated orgs (bank, hospital, defense, utility). Script: last critical CVE fire drill, hours spent, who they asked, what evidence they kept, air-gap update process. **Kill criterion:** if \< 50% report multi-hour manual triage per critical CVE, rescope. - \[ \] Hand-write 5 ECPs (regreSSHion CVE-2024-6387, Log4Shell CVE-2021-44228, Spring4Shell CVE-2022-22965, xz backdoor CVE-2024-3094, IngressNightmare CVE-2025-1974) to stress-test the schema against real precondition diversity (version+config, JVM class presence, platform+deployment mode, distro-specific build, K8s exposure). - \[ \] ADRs: Go vs alternatives, SQLite/Postgres, OCI bundles, cosign keyed, 3-valued semantics.

**Phase 1: MVP "Fire Drill" (6–8 weeks)** → see §12 - Engine + pack schema + 25 reviewed packs with fixtures. - KB bundle build/verify/import (OSV, distro feeds for RHEL/Ubuntu/Debian/Alpine, KEV, EPSS, CVE5). - Inputs: SBOM import (CycloneDX/SPDX), Trivy/Grype JSON import, SSH collector (Linux), K8s collector. - Exposure: zone labels + K8s Service/Ingress/NetworkPolicy. - Outputs: funnel UI, evidence view, NEEDS REVIEW resolution hints, OpenVEX + CycloneDX VEX, PDF brief, JSON. - AuthN local + OIDC. Audit log. SQLite. - `verdict-bench` v0 with ground truth for all 25 packs. CI gate: false NOT AFFECTED = 0.

**Phase 2: Verify (4–6 weeks)** - Sandbox runner (rootless Podman, hardened) + probe registry + OPA policy + evidence attestations + fidelity score. - Watch mode + verdict flip alerts. Control attestations with expiry. - Ticket push (Jira DC, ServiceNow), Dependency-Track VEX push, Nessus import.

**Phase 3: Depth (6–8 weeks)** - Firecracker/Kata sandbox (kernel CVEs). - Batfish-based network path for firewall/router configs. - `code_reachable` via govulncheck. Analyzer plugin interface for others. - CSAF VEX + PSIRT "product" mode. - Postgres, HA notes, LDAP.

**Phase 4: Enterprise hardening (ongoing)** - FIPS build, SELinux module, STIG checklist, RPM/DEB, Helm, offline upgrade/rollback. - Customer trust roots + re-signing workflow. - Optional local-LLM pack drafting (draft-only, with an injection-resistance test suite). - WinRM collector, appliance config importers (edge VPNs/firewalls are frequent KEV entries).

### 11.4 Test strategy

- **Unit:** version comparison tables (rpm/dpkg/apk edge cases), parsers (golden configs incl. Include/Match), 3-valued logic truth tables.
- **Property:** invariants from §11.1 (#2, #3).
- **Pack tests:** every reviewed pack's fixtures build in CI and produce the expected verdict/justification.
- **E2E:** docker-compose/kind lab with \~20 assets mixing vuln/fixed/mitigated/unknown-permission/unknown-zone. Assert the funnel numbers exactly.
- **Air-gap test:** full drill in a no-network namespace.
- **Security:** fuzz pack loader and parsers (`go test -fuzz`), SSH-allowlist injection tests, redaction tests, sandbox escape smoke tests (egress attempts must be blocked and logged).

### 11.5 Definition of done for MVP

- A new user on a fresh offline VM gets from installer → first drill on their own SBOMs in \< 30 min, following README only.
- On `verdict-bench`: 0 false NOT AFFECTED, ≥ 90% EXPLOITABLE precision, ≥ 70% determinate.
- Drill on the regreSSHion fixture lab shows the exact funnel from §2.3, with resolution hints for every NEEDS REVIEW.
- OpenVEX output validates and imports into Dependency-Track and suppresses the corresponding findings.
- Threat model + security-review-pack docs exist.

---

## 12. Recommended minimal viable scope (the one-paragraph answer)

**Ship "Fire Drill for Linux + Kubernetes" first:** a single Go binary that imports a signed offline knowledge bundle, ingests SBOMs/Trivy output, and collects read-only facts over SSH and the K8s API. It evaluates 25 hand-built, fixture-tested condition packs for the CVEs AppSec teams actually got paged for, and shows the exposure funnel with evidence, explicit unknowns + how to resolve them, and OpenVEX/PDF export. **No sandbox, no LLM, no Batfish, no code reachability in v0.1.** Those add confidence later. The MVP already removes the hours of "go check this config on 40 hosts", and it does so in a true air-gap. If the fire drill isn't loved, nothing built on top will save it.

---

## 13. Assumptions & confidence

| Assumption | Confidence | How to validate |
| --- | --- | --- |
| Fire-drill triage costs regulated AppSec teams hours per critical CVE | High (practitioner experience, consistent with industry data) | Phase 0 interviews |
| The community will author packs if tooling is good | Medium | Seed 25. Measure external PRs in first 90 days. Fallback: maintainers + vendor PSIRTs cover KEV only |
| Read-only SSH/K8s collectors pass regulated change boards | Medium | Pilot security reviews. Fallback: config-zip upload + SBOM-only mode |
| Precondition checks (no exploit) give enough confidence for most decisions | Medium-High | Bench + pilot feedback on how often sandbox is requested |
| OCI + cosign keyed fits customer transfer processes | Medium-High | Pilot with a T0 customer. Fallback: plain tar + detached sig |
| Time-to-exploit figures (hours) | Medium (sources conflict) | Re-check M-Trends 2026 original |

## 14. Open questions

1. Final name + trademark check.
2. Governance for pack review: maintainers only, or a trusted-reviewer program for vendor PSIRTs?
3. Do we accept a *runtime* evidence source (eBPF snapshot) in v1, given regulated orgs' aversion to agents? (Leaning: optional one-shot snapshot binary, not a resident agent.)
4. CSAF VEX vs OpenVEX as the canonical internal format. (Leaning: internal model → export to all three.)
5. How do we handle CVEs in vendor appliances with no SBOM (Fortinet, Ivanti, Citrix: frequent KEV)? Config/version import parsers per vendor, likely Phase 4. High value, high effort.

---

## Sources

- Safeguard — what share of vulnerabilities get exploited: https://safeguard.sh/resources/blog/what-share-of-vulnerabilities-actually-get-exploited
- Axis Intelligence — exploitation statistics 2026: https://axis-intelligence.com/vulnerability-exploitation-statistics/
- Ayi NEDJIMI Consultants — H1 2026 CVE recap: https://ayinedjimi-consultants.fr/news/bilan-cve-h1-2026-35000-vulnerabilites
- Trend Micro — Making sense of the vulnpocalypse (2026): https://www.trendmicro.com/en/research/26/g/making-sense-of-the-vulnpocalypse.html
- opensourcesecurity.io — VulnCheck state of exploitation (2026-08): https://opensourcesecurity.io/2026/2026-08-vulncheck-state-of-exploitation/
- Help Net Security — NIST NVD enrichment change (2026-04-16): https://helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment
- CSA — NVD enrichment overhaul research note (2026-04-29): https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/
- CSA — CISO daily briefing (2026-05-12): https://labs.cloudsecurityalliance.org/research-rb/ciso-daily-briefing-20260512/
- Aviatrix — AI-assisted exploit development (2026): https://aviatrix.ai/threat-research-center/ai-assisted-exploit-development-outpaces-scanner-detection-2026
- Endor Labs — SCA with reachability: https://www.endorlabs.com/lp/sca-with-reachability
- Socket — reachability docs: https://docs.socket.dev/docs/reachability-analysis
- Black Duck — reachability limits: https://www.blackduck.com/blog/vulnerability-reachability-in-sca.html
- Jones Day — CRA 24h reporting (2026-07): https://www.jonesday.com/en/insights/2026/07/eu-cyber-resilience-act-24hour-reporting-duties-start-september-11-2026
- European Commission — CRA reporting: https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- BitVex (offline OpenVEX for Yocto): https://docs.rs/crate/bitvex/0.3.0/source/README.md
- OpenVEX: https://github.com/openvex