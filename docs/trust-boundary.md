# Evidence trust boundary

v0.1 does not collect evidence. It evaluates evidence you put in a JSON snapshot. `scripts/collect-host.sh` is a script you run on a host yourself. Its output is imported as `observed` and `high`, except an OpenSSH version read from an unpackaged sshd's `sshd -V` banner, which is `observed` and `medium` and can therefore support affected but never not_affected (threat model A51). Verdict cannot tell that the file came from that script or that host, so it is caller-asserted like any other snapshot input.

`evidence_trust` must be the string `caller_asserted`. Any other value, including `verified`, `signed`, or `high`, is rejected. The report then labels every verdict `evidence_trust: caller_asserted_unverified`.

That label means:

- Confidence (`low`, `medium`, `high`, `confirmed`) is copied from the snapshot, then capped by the pack's `confidence_ceiling`. The engine does not raise it.
- A package may carry its own `confidence`. It only lowers the inventory's for checks that match that package; it never raises it.
- `basis: observed` means the caller says the value was read, as opposed to inferred or attested. The engine cannot tell whether that claim is true.
- A high-confidence observed fact can satisfy the **logical** bar for `not_affected` on a reviewed pack. It does not satisfy an authenticity bar. There is no signature, no TPM quote, and no collector identity in this version.
- `basis: inferred` is discarded (the leaf is unknown).
- `basis: attested` may participate in a true/false Kleene value, including an `affected` result, and is never treated as observed. An attestation cannot by itself produce `not_affected`.
- Demo snapshots under `examples/snapshots/` are synthetic lab data written for this repository. They are not observations of a real fleet.

Operators who need an audit trail have to wrap this tool: record who produced the snapshot, how, and under what change control. That wrapper does not exist here.

Related decision: `docs/adr/0004-evidence-trust-boundary.md`.
