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
6. A real CVE pack additionally needs a review record outside the YAML file. `verdict pack review --pack <file> --record <file>` checks that record. It must name the pack id, the content SHA-256 (print it with `verdict pack hash <file>`; output `pack_sha256=<hex> pack=<id> file=<path>`), and two distinct reviewers, each with a statement and an RFC3339 time. The content hash is of the decoded pack with `status` and `reviewers` cleared, so writing those two fields during promotion does not change it. Any other edit does. `synthetic-reviewer-*` names cannot sign a real CVE. The command does not edit the pack. A human copies the accepted names into `reviewers` and sets `status: reviewed` only after that check passes. Editing `reviewers` inside the pack is not that record. Until such a record exists, seed CVE packs stay draft. CI rejects a non-synthetic pack with status `reviewed` or a non-empty reviewer list.

regreSSHion is not promoted. There is no record of two human reviewers for its current bytes. The bench scores it with fixture names in memory so a false `not_affected` still fails CI.

The engine enforces (1) and (2) and the ceiling. It does not know whether a name belongs to a real person. Repository policy and review process have to enforce that. Trusting the YAML is the same class of limitation as trusting the snapshot; `docs/trust-boundary.md` applies to packs a caller passes on the command line as well. Packs **shipped in this repository** are held to the stricter rule by `TestRepositoryPackPolicy`.

## Signed review records

A review record can carry a signature per reviewer, so a record that names two people is evidence that two holders of trusted keys signed this exact content. The flow for a real CVE pack:

1. Each reviewer, once, makes a key pair on their own machine: `verdict bundle keygen --private-key ~/verdict-review.key --public-key review.pub` (the bundle Ed25519 PEM format). A maintainer adds the public key to `packs/reviewer-keys/<key_id>.pub` in a reviewed PR; `key_id` is printed by `keygen`. The private key never enters the repository.
2. The pack author prints the content hash with `verdict pack hash <file>`.
3. Each reviewer reviews the pack and runs, themselves:

   ```bash
   verdict pack sign-review --pack <file> --key ~/verdict-review.key --reviewer "Full Name" \
     --statement "What I checked and concluded" --reviewed-at <RFC3339>
   ```

   It prints a reviewer entry with `key_id` and `signature`: base64 Ed25519 over `verdict-pack-review/v1\n<pack_id>\n<pack_sha256>\n<name>\n`. It refuses `synthetic-reviewer-*` names on a real pack. It does not read the clock or edit anything.
4. The entries go into one record, `packs/reviews/<pack_id>/<anything>.json` (`pack_id`, `pack_sha256`, `reviewers`). Check it with `verdict pack review --pack <file> --record <record> --reviewer-keys packs/reviewer-keys --require-signatures`.
5. Only then does a human set `status: reviewed` and copy the same names into `reviewers`.

CI runs `verdict pack check-reviews`: every non-synthetic pack with `status: reviewed` needs a record under `packs/reviews/<pack_id>/` that `pack review` accepts, whose reviewers equal the pack's, and in which every reviewer's signature verifies against `packs/reviewer-keys/`. Synthetic `CVE-2099-*` packs use fixture reviewers and are not checked. `TestRepositoryPackPolicy` still refuses any reviewed real pack today; relaxing it to defer to this gate is a separate, reviewed change.

What a signature covers: the pack id, the content hash, and the name. It does not cover `reviewed_at` or `statement`, which stay unauthenticated text. Any change to the pack content changes the hash and voids every signature. A forged record fails: unsigned entries, signatures from keys not in `packs/reviewer-keys/`, a key file whose content is not the key its name says, one key signing for two names, and a record re-pointed at edited pack content.

Coding agents never run `sign-review`, never hold a reviewer key, and never write records or key files ([AGENTS.md](../AGENTS.md)).

## Quorum is not authenticity

Two strings in a YAML list are not a cryptographic review. Signed review records (above) bind a review to a key, but the trusted key directory is only as trustworthy as the repository's review of changes to it, and there is no key revocation, expiry, or transparency log. Signed packs are not implemented. Customers who need "nothing runs unless we signed it" cannot get that from v0.1.

## Author

Pack drafts in this repository list Uddeshya Kumar as the draft author. That credits the encoding work. It is not a claim of having reviewed the pack, of coordinating with the vendor, or of having reproduced an exploit.
