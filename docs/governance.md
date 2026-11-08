# Pack governance and reviewer policy

This document is the policy for condition packs in this repository. It is not a description of a review that has already happened for a real CVE.

## States

| Status | Who may set it | `not_affected` |
| --- | --- | --- |
| `draft` | Any contributor | Never. The engine withholds it even if the tree is strictly false |
| `reviewed` | Two distinct human reviewers, with a public review record | Possible, if the proof rules also hold |
| `deprecated` | A maintainer, with a reason in the pack | Never |

`confidence_ceiling` caps every confidence the pack reports. A ceiling below `high` also makes `not_affected` impossible, including on a reviewed pack.

## Reviewed means all of the following

1. `status: reviewed`.
2. `reviewers` lists at least two different non-empty names.
3. The reviewers are humans who reviewed the pack. Fixture names `synthetic-reviewer-alpha` and `synthetic-reviewer-beta` are reserved for `synthetic: true` packs whose CVE id is `CVE-2099-*`. They are not reviewers of regreSSHion, Log4Shell, or any other real advisory.
4. `tests` covers at least one case expected to be affected and one case expected to be `not_affected` or `needs_review` for the reason the pack claims. v0.1 runs those tests against local JSON snapshots, not containers.
5. Sources point at the advisories the checks were taken from. Uncertain preconditions stay in `limitations` instead of being encoded as falsifying checks.
6. A real CVE pack additionally needs a review record outside the YAML file. `verdict pack review --pack <file> --record <file>` checks that record. It must name the pack id, the SHA-256 of the pack bytes, and two distinct reviewers, each with a statement and an RFC3339 time. `synthetic-reviewer-*` names cannot sign a real CVE. The command does not edit the pack. A human copies the accepted names into `reviewers` and sets `status: reviewed` only after that check passes. Editing `reviewers` inside the pack is not that record. Until such a record exists, seed CVE packs stay draft. CI rejects a non-synthetic pack with status `reviewed` or a non-empty reviewer list.

regreSSHion is not promoted. There is no record of two human reviewers for its current bytes. The bench scores it with fixture names in memory so a false `not_affected` still fails CI.

The engine enforces (1) and (2) and the ceiling. It does not know whether a name belongs to a real person. Repository policy and review process have to enforce that. Trusting the YAML is the same class of limitation as trusting the snapshot; `docs/trust-boundary.md` applies to packs a caller passes on the command line as well. Packs **shipped in this repository** are held to the stricter rule by `TestRepositoryPackPolicy`.

## Quorum is not authenticity

Two strings in a YAML list are not a cryptographic review. Signed packs, a reviewer key ring, and a transparency log are not implemented. Customers who need "nothing runs unless we signed it" cannot get that from v0.1.

## Author

Pack drafts in this repository list Uddeshya Kumar as the draft author. That credits the encoding work. It is not a claim of having reviewed the pack, of coordinating with the vendor, or of having reproduced an exploit.
