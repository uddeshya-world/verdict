// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/uddeshya-world/verdict/internal/diff"
	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/export/openvex"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/reportschema"
)

// Limits on what one call returns or reads.
const (
	defaultMaxAssets = 100
	maxMaxAssets     = 1000
	maxPathsPerCall  = 50
	maxListedPacks   = 500
)

type annotations struct {
	Title           string `json:"title"`
	ReadOnlyHint    bool   `json:"readOnlyHint"`
	DestructiveHint bool   `json:"destructiveHint"`
	IdempotentHint  bool   `json:"idempotentHint"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

type toolDef struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations annotations    `json:"annotations"`
}

type tool struct {
	def toolDef
	run func(s *Server, args json.RawMessage) (any, error)
}

// argError is a malformed tools/call arguments object: answered as JSON-RPC
// invalid params, not as a tool result.
type argError struct{ msg string }

func (e *argError) Error() string { return e.msg }

// toolError is a failure the tool reports in its result with isError true.
// msg is the server's own text; detail comes from the CLI or a file and is
// placed under untrusted.
type toolError struct {
	kind, msg, detail string
}

func (e *toolError) Error() string { return e.kind + ": " + e.msg }

func schemaObj(props map[string]any, required ...string) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func boolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func pathsProp(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "maxItems": maxPathsPerCall, "description": desc}
}

func def(name, title, desc string, schema map[string]any) toolDef {
	return toolDef{Name: name, Title: title, Description: desc, InputSchema: schema, Annotations: annotations{
		Title: title, ReadOnlyHint: true, DestructiveHint: false, IdempotentHint: true, OpenWorldHint: false,
	}}
}

const pathNote = " Paths are relative to the server root; paths outside it are refused."

// tools is the complete tool surface. internal/mcp tests pin the names: a
// tool that writes facts, packs, reviews, bundles, or keys is never added.
var tools = []tool{
	{def("verdict_drill", "Drill a pack against a snapshot",
		"Evaluate one condition pack against a local snapshot with the verdict engine. Returns the summary and, per asset, state, vex_status, confidence, reason codes, evidence ids, and hints with the catalog actor and next action. Writes the canonical report (and optionally OpenVEX) under .verdict-out/ and returns its path. An asset is not affected only when its state is not_affected."+pathNote,
		schemaObj(map[string]any{
			"pack":       strProp("condition pack YAML"),
			"snapshot":   strProp("snapshot JSON"),
			"policy":     strProp("site zone policy JSON; without it exposure stays unknown"),
			"asset":      strProp("evaluate only this asset id"),
			"openvex":    boolProp("also write an OpenVEX document under .verdict-out/"),
			"max_assets": map[string]any{"type": "integer", "minimum": 1, "maximum": maxMaxAssets, "description": "assets returned in the result (default 100); the report file has all"},
		}, "pack", "snapshot")), toolDrill},
	{def("verdict_explain", "Explain reason codes",
		"Return reason catalog entries: kind, hint, next_action, and the actor who can resolve each code (human, collector, reviewer, none). Give codes, or all: true.",
		schemaObj(map[string]any{
			"codes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 100, "description": "reason codes"},
			"all":   boolProp("return every catalog entry"),
		})), toolExplain},
	{def("verdict_missing_facts", "List what NEEDS REVIEW is missing",
		"For needs_review assets, group the leaf hints by fact key, with the reason codes, the catalog actor who must act, and the next action. Give a drill report (report), or a pack and snapshot to drill first. The facts listed are requests for a human or collector; never supply them yourself."+pathNote,
		schemaObj(map[string]any{
			"report":   strProp("drill report JSON (for example one under .verdict-out/)"),
			"pack":     strProp("condition pack YAML (with snapshot, instead of report)"),
			"snapshot": strProp("snapshot JSON (with pack)"),
			"policy":   strProp("site zone policy JSON (with pack)"),
			"asset":    strProp("only this asset id (with pack)"),
		})), toolMissingFacts},
	{def("verdict_diff", "Compare two drill reports",
		"Compare two drill reports for the same pack and CVE asset by asset (verdict diff --json). Regression: into exploitable, or out of not_affected. A removed asset is not evidence of anything."+pathNote,
		schemaObj(map[string]any{
			"before":  strProp("drill report before the change"),
			"after":   strProp("drill report after the change"),
			"fail_on": map[string]any{"type": "string", "enum": []string{diff.FailOnRegression, diff.FailOnAnyAffectedChange, diff.FailOnAny}, "description": "policy for matched (default regression)"},
		}, "before", "after")), toolDiff},
	{def("verdict_pack_lint", "Lint condition packs",
		"Load packs with the strict loader and linter (verdict pack lint --json)."+pathNote,
		schemaObj(map[string]any{"paths": pathsProp("pack YAML files")}, "paths")), toolPackLint},
	{def("verdict_pack_test", "Run a pack's declared fixtures",
		"Run each pack's declared snapshot fixtures in process (verdict pack test --json). Fixture paths named in the pack must also be inside the server root."+pathNote,
		schemaObj(map[string]any{"paths": pathsProp("pack YAML files")}, "paths")), toolPackTest},
	{def("verdict_pack_hash", "Pack review content hash",
		"Print the review content hash (pack_sha256) of packs (verdict pack hash --json). Read-only; it does not review or promote anything."+pathNote,
		schemaObj(map[string]any{"paths": pathsProp("pack YAML files")}, "paths")), toolPackHash},
	{def("verdict_openvex_validate", "Validate an OpenVEX document",
		"Validate an OpenVEX document against the schema embedded in the binary."+pathNote,
		schemaObj(map[string]any{"path": strProp("OpenVEX JSON file")}, "path")), toolOpenVEXValidate},
	{def("verdict_report_validate", "Validate drill reports",
		"Validate drill reports against the embedded report schema and the reason catalog."+pathNote,
		schemaObj(map[string]any{"paths": pathsProp("drill report JSON files")}, "paths")), toolReportValidate},
	{def("verdict_list_packs", "List condition packs",
		"List condition packs (*.yaml, *.yml) under a directory with their status, CVE, confidence ceiling, and test count. Draft and deprecated packs never produce not_affected."+pathNote,
		schemaObj(map[string]any{"dir": strProp("directory to search (default packs)")})), toolListPacks},
}

func toolList() []toolDef {
	out := make([]toolDef, len(tools))
	for i, t := range tools {
		out[i] = t.def
	}
	return out
}

// ToolNames returns the exposed tool names in order.
func ToolNames() []string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = t.def.Name
	}
	return out
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) callTool(req request) *response {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
		return errResp(req.ID, codeInvalidParams, "invalid params: tools/call takes name and arguments")
	}
	var t *tool
	for i := range tools {
		if tools[i].def.Name == p.Name {
			t = &tools[i]
		}
	}
	if t == nil {
		return errResp(req.ID, codeInvalidParams, "unknown tool; tools/list names every tool")
	}
	payload, err := t.run(s, p.Arguments)
	var ae *argError
	if errors.As(err, &ae) {
		return errResp(req.ID, codeInvalidParams, "invalid params: "+ae.msg)
	}
	if err != nil {
		var te *toolError
		if !errors.As(err, &te) {
			te = &toolError{kind: "internal_error", msg: "the tool failed", detail: err.Error()}
		}
		errObj := map[string]any{"kind": te.kind, "message": te.msg}
		if te.detail != "" {
			errObj["untrusted"] = map[string]any{"detail": clean(s.scrub(te.detail))}
		}
		payload = map[string]any{"ok": false, "error": errObj}
		return &response{JSONRPC: "2.0", ID: req.ID, Result: s.wrap(t.def.Name, payload, true)}
	}
	return &response{JSONRPC: "2.0", ID: req.ID, Result: s.wrap(t.def.Name, payload, false)}
}

// wrap builds a tools/call result: structuredContent is the payload plus
// _meta, and the one text block is that same JSON, with no prose around it.
func (s *Server) wrap(name string, payload any, isErr bool) map[string]any {
	meta := map[string]any{"note": UntrustedNote, "invariant": invariantNote, "server": "verdict-mcp", "tool": name}
	body, err := json.Marshal(payload)
	var structured map[string]any
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		err = dec.Decode(&structured)
	}
	if err != nil || structured == nil {
		structured, isErr = map[string]any{"ok": false, "error": map[string]any{"kind": "internal_error", "message": "unencodable result"}}, true
	}
	structured["_meta"] = meta
	var text bytes.Buffer
	enc := json.NewEncoder(&text)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(structured)
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": strings.TrimSuffix(text.String(), "\n")}},
		"structuredContent": structured,
		"isError":           isErr,
		"_meta":             meta,
	}
}

// scrub replaces the absolute root in CLI messages with ".", so results do
// not carry the server's filesystem layout.
func (s *Server) scrub(msg string) string {
	for _, r := range []string{s.root, s.rootLexical} {
		msg = strings.ReplaceAll(msg, r+string(filepath.Separator), "")
		msg = strings.ReplaceAll(msg, r, ".")
	}
	return msg
}

func decodeArgs(raw json.RawMessage, v any) error {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		t = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var ute *json.UnmarshalTypeError
		switch {
		case errors.As(err, &ute):
			return &argError{fmt.Sprintf("argument %s has the wrong type", ute.Field)}
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			return &argError{"unknown argument " + clean(strings.TrimPrefix(err.Error(), "json: unknown field "))}
		}
		return &argError{"arguments must be one JSON object"}
	}
	if dec.More() {
		return &argError{"arguments must be one JSON object"}
	}
	return nil
}

// path resolves one argument path, naming the argument in the error.
func (s *Server) path(arg, p string) (string, error) {
	real, err := s.resolve(p)
	if err != nil {
		kind := "path_rejected"
		if errors.Is(err, errEscape) {
			kind = "path_outside_root"
		}
		return "", &toolError{kind: kind, msg: arg + ": " + err.Error()}
	}
	return real, nil
}

// file resolves a path argument that must be a regular file of at most max
// bytes: no FIFO or device that would block a read, no file larger than the
// command that reads it accepts.
func (s *Server) file(arg, p string, max int64) (string, error) {
	real, err := s.path(arg, p)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return "", &toolError{kind: "path_rejected", msg: arg + ": not a regular file"}
	}
	if fi.Size() > max {
		return "", &toolError{kind: "input_error", msg: fmt.Sprintf("%s: file is %d bytes, over the %d-byte cap", arg, fi.Size(), max)}
	}
	return real, nil
}

func (s *Server) paths(arg string, ps []string, max int64) ([]string, error) {
	if len(ps) == 0 {
		return nil, &argError{arg + " is required"}
	}
	if len(ps) > maxPathsPerCall {
		return nil, &argError{fmt.Sprintf("%s takes at most %d paths", arg, maxPathsPerCall)}
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		real, err := s.file(fmt.Sprintf("%s[%d]", arg, i), p, max)
		if err != nil {
			return nil, err
		}
		out[i] = real
	}
	return out, nil
}

// cli runs one verdict command. Every path in args is an absolute path
// inside the root, so no argument can be read as a flag.
func (s *Server) cli(args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	err := s.cfg.Run(args, &stdout, &stderr)
	return stdout.Bytes(), err
}

func (s *Server) snapCap() string {
	return "--max-snapshot-bytes=" + strconv.FormatInt(s.cfg.MaxSnapshotBytes, 10)
}

func cliFailure(err error) error {
	return &toolError{kind: "input_error", msg: "verdict refused the input", detail: err.Error()}
}

// ---- verdict_drill ----

type drillArgs struct {
	Pack      string `json:"pack"`
	Snapshot  string `json:"snapshot"`
	Policy    string `json:"policy"`
	Asset     string `json:"asset"`
	OpenVEX   bool   `json:"openvex"`
	MaxAssets *int   `json:"max_assets"`
}

type drillRun struct {
	rep     *engine.Report
	report  string
	openvex string
}

func (s *Server) runDrill(a drillArgs) (*drillRun, error) {
	if a.Pack == "" || a.Snapshot == "" {
		return nil, &argError{"pack and snapshot are required"}
	}
	pk, err := s.file("pack", a.Pack, pack.MaxBytes)
	if err != nil {
		return nil, err
	}
	sn, err := s.file("snapshot", a.Snapshot, s.cfg.MaxSnapshotBytes)
	if err != nil {
		return nil, err
	}
	args := []string{"drill", "--pack", pk, "--snapshot", sn, "--invoked-by", s.invokedBy, s.snapCap()}
	if a.Policy != "" {
		pol, err := s.file("policy", a.Policy, s.cfg.MaxSnapshotBytes)
		if err != nil {
			return nil, err
		}
		args = append(args, "--policy", pol)
	}
	if a.Asset != "" {
		args = append(args, "--asset="+a.Asset)
	}
	body, err := s.cli(args...)
	if err != nil {
		return nil, cliFailure(err)
	}
	var rep engine.Report
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, &toolError{kind: "internal_error", msg: "drill output was not a report"}
	}
	sum := sha256.Sum256(body)
	base := "drill-" + hex.EncodeToString(sum[:8])
	run := &drillRun{rep: &rep}
	if run.report, err = s.writeOut(base+".json", body); err != nil {
		return nil, &toolError{kind: "output_error", msg: "could not write the report under " + OutDirName, detail: err.Error()}
	}
	if a.OpenVEX {
		doc, err := openvex.FromReport(&rep, s.invokedBy)
		if err != nil {
			return nil, &toolError{kind: "internal_error", msg: "openvex export failed", detail: err.Error()}
		}
		raw, err := openvex.Marshal(doc)
		if err != nil {
			return nil, &toolError{kind: "internal_error", msg: "openvex export failed", detail: err.Error()}
		}
		if run.openvex, err = s.writeOut(base+".openvex.json", raw); err != nil {
			return nil, &toolError{kind: "output_error", msg: "could not write OpenVEX under " + OutDirName, detail: err.Error()}
		}
	}
	return run, nil
}

func toolDrill(s *Server, raw json.RawMessage) (any, error) {
	var a drillArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	limit := defaultMaxAssets
	if a.MaxAssets != nil {
		if *a.MaxAssets < 1 || *a.MaxAssets > maxMaxAssets {
			return nil, &argError{fmt.Sprintf("max_assets must be 1-%d", maxMaxAssets)}
		}
		limit = *a.MaxAssets
	}
	run, err := s.runDrill(a)
	if err != nil {
		return nil, err
	}
	rep := run.rep
	assets := []assetOut{}
	for i, v := range rep.Verdicts {
		if i == limit {
			break
		}
		assets = append(assets, verdictView(v))
	}
	out := map[string]any{
		"ok":              true,
		"report":          run.report,
		"pack_status":     enum(packStatuses, rep.PackStatus),
		"evaluation_time": rep.EvaluationTime,
		"invoked_by":      s.invokedBy,
		"evidence_trust":  enum(set("caller_asserted_unverified"), rep.EvidenceTrust),
		"summary":         rep.Summary,
		"assets_total":    len(rep.Verdicts),
		"assets_returned": len(assets),
		"truncated":       len(assets) < len(rep.Verdicts),
		"assets":          assets,
		"untrusted":       reportUntrusted(rep),
	}
	if cveRE.MatchString(rep.CVE) {
		out["cve"] = rep.CVE
	}
	if run.openvex != "" {
		out["openvex"] = run.openvex
	}
	return out, nil
}

func reportUntrusted(rep *engine.Report) map[string]any {
	u := map[string]any{"pack_id": clean(rep.PackID), "kb_version": clean(rep.KBVersion)}
	if !cveRE.MatchString(rep.CVE) {
		u["cve"] = clean(rep.CVE)
	}
	return u
}

type assetOut struct {
	State               string         `json:"state"`
	VEXStatus           string         `json:"vex_status"`
	Justification       string         `json:"justification,omitempty"`
	Confidence          string         `json:"confidence"`
	ExposureUncertainty bool           `json:"exposure_uncertainty"`
	Reasons             []string       `json:"reasons"`
	EvidenceIDs         []string       `json:"evidence_ids"`
	OperatorEdits       int            `json:"operator_edits,omitempty"`
	Hints               []hintOut      `json:"hints"`
	Untrusted           assetUntrusted `json:"untrusted"`
}

type assetUntrusted struct {
	AssetID     string   `json:"asset_id"`
	AssetName   string   `json:"asset_name"`
	AssetKind   string   `json:"asset_kind,omitempty"`
	PrimaryPURL string   `json:"primary_purl,omitempty"`
	Zones       []string `json:"zones,omitempty"`
	Reasons     []string `json:"reasons,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

func verdictView(v engine.Verdict) assetOut {
	out := assetOut{
		State:               enum(states, v.State),
		VEXStatus:           enum(vexStatuses, v.VEXStatus),
		Justification:       enum(justifications, v.Justification),
		Confidence:          enum(confidences, v.Confidence),
		ExposureUncertainty: v.ExposureUncertainty,
		Reasons:             []string{},
		OperatorEdits:       v.OperatorEdits,
		Hints:               []hintOut{},
		Untrusted: assetUntrusted{
			AssetID: clean(v.AssetID), AssetName: clean(v.AssetName), AssetKind: clean(v.AssetKind),
			PrimaryPURL: clean(v.PrimaryPURL), Zones: cleanList(v.Zones),
		},
	}
	for _, r := range v.Reasons {
		if _, ok := engine.Reasons[r]; ok {
			out.Reasons = append(out.Reasons, r)
		} else {
			out.Untrusted.Reasons = append(out.Untrusted.Reasons, clean(r))
		}
	}
	seen := map[string]bool{}
	var ids []string
	add := func(list []string) {
		for _, id := range list {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	for _, l := range v.Leaves {
		add(l.EvidenceIDs)
	}
	add(v.ExposureEvidenceIDs)
	if v.Proof != nil {
		add(v.Proof.EvidenceIDs)
	}
	sort.Strings(ids)
	out.EvidenceIDs, out.Untrusted.EvidenceIDs = splitIDs(ids)
	for _, h := range v.Hints {
		out.Hints = append(out.Hints, hintView(h))
	}
	return out
}

type hintOut struct {
	CheckID    string         `json:"check_id,omitempty"`
	Reason     string         `json:"reason"`
	Kind       string         `json:"kind,omitempty"`
	Actor      string         `json:"actor,omitempty"`
	NextAction string         `json:"next_action,omitempty"`
	Hint       string         `json:"hint,omitempty"`
	Untrusted  *hintUntrusted `json:"untrusted,omitempty"`
}

type hintUntrusted struct {
	CheckID      string  `json:"check_id,omitempty"`
	Reason       string  `json:"reason,omitempty"`
	Detail       *string `json:"detail,omitempty"`
	PackHint     string  `json:"pack_hint,omitempty"`
	RenderedHint string  `json:"rendered_hint,omitempty"`
}

// Placeholders that stand in trusted hint text for the untrusted parts.
const (
	phDetail   = "[untrusted.detail]"
	phRendered = "[see untrusted.rendered_hint]"
	phCheck    = "[untrusted.check_id]"
)

func fillHint(tmpl, check, detail string) string {
	return strings.NewReplacer("{check}", check, "{detail_q}", detail, "{detail}", detail).Replace(tmpl)
}

// hintView splits a report hint into catalog text (trusted) and the detail,
// pack resolution_hint, or whole rendered text (untrusted). Catalog text is
// trusted only when the split is exact; otherwise the rendered hint is
// untrusted and the trusted hint is the catalog template with a placeholder.
func hintView(h engine.Hint) hintOut {
	u := &hintUntrusted{}
	out := hintOut{}
	info, known := engine.Reasons[h.Reason]
	if known {
		out.Reason = h.Reason
	} else {
		out.Reason = "unrecognized"
		u.Reason = clean(h.Reason)
	}
	check := h.CheckID
	checkOK := check == "" || checkIDRE.MatchString(check)
	if checkOK {
		out.CheckID = check
	} else {
		u.CheckID = clean(check)
		check = phCheck
	}
	if !known {
		u.RenderedHint = clean(h.Hint)
		out.Untrusted = u
		return out
	}
	out.Kind, out.Actor, out.NextAction = info.Kind, info.Actor, info.NextAction
	switch {
	case info.Kind == engine.KindLeaf && h.CheckID != "":
		detail, hasDetail, packHint, ok := engine.ParseLeafHint(h.Reason, h.CheckID, h.Hint)
		if ok && checkOK {
			out.Hint = fillHint(info.Hint, check, phDetail)
			if hasDetail {
				d := clean(detail)
				u.Detail = &d
			}
			u.PackHint = clean(packHint)
		} else {
			out.Hint = fillHint(info.Hint, check, phRendered)
			u.RenderedHint = clean(h.Hint)
		}
	case h.Hint == info.Hint || info.DecisionHint != "" && h.Hint == info.DecisionHint:
		out.Hint = h.Hint
	default:
		out.Hint = fillHint(info.Hint, check, phRendered)
		u.RenderedHint = clean(h.Hint)
	}
	if *u != (hintUntrusted{}) {
		out.Untrusted = u
	}
	return out
}

// ---- verdict_explain ----

type explainArgs struct {
	Codes []string `json:"codes"`
	All   bool     `json:"all"`
}

func toolExplain(_ *Server, raw json.RawMessage) (any, error) {
	var a explainArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.All == (len(a.Codes) > 0) {
		return nil, &argError{"give codes, or all: true"}
	}
	codes := a.Codes
	if a.All {
		codes = engine.ReasonCodes()
	}
	type entry struct {
		Code string `json:"code"`
		engine.ReasonInfo
	}
	out := []entry{}
	for _, c := range codes {
		info, ok := engine.Reasons[c]
		if !ok {
			return nil, &toolError{kind: "unknown_reason", msg: "unknown reason code; call with all: true to list them", detail: c}
		}
		out = append(out, entry{Code: c, ReasonInfo: info})
	}
	return map[string]any{"ok": true, "reasons": out}, nil
}

// ---- verdict_missing_facts ----

type missingArgs struct {
	Report   string `json:"report"`
	Pack     string `json:"pack"`
	Snapshot string `json:"snapshot"`
	Policy   string `json:"policy"`
	Asset    string `json:"asset"`
}

type reasonAction struct {
	Reason     string `json:"reason"`
	Actor      string `json:"actor"`
	NextAction string `json:"next_action"`
	Hint       string `json:"hint"`
}

type factGroup struct {
	CheckIDs  []string       `json:"check_ids"`
	Reasons   []reasonAction `json:"reasons"`
	Actors    []string       `json:"actors"`
	Assets    int            `json:"assets"`
	Untrusted groupUntrusted `json:"untrusted"`
	assetSeen map[string]bool
	sortKey   string
}

type groupUntrusted struct {
	// FactKey is the hint's detail (a fact key or an advisory key). It is
	// empty when the hint carries none or could not be split.
	FactKey   string   `json:"fact_key"`
	AssetIDs  []string `json:"asset_ids"`
	PackHints []string `json:"pack_hints,omitempty"`
	CheckIDs  []string `json:"check_ids,omitempty"`
}

func toolMissingFacts(s *Server, raw json.RawMessage) (any, error) {
	var a missingArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	var rep *engine.Report
	out := map[string]any{"ok": true}
	switch {
	case a.Report != "" && a.Pack == "" && a.Snapshot == "" && a.Policy == "" && a.Asset == "":
		p, err := s.file("report", a.Report, s.cfg.MaxSnapshotBytes)
		if err != nil {
			return nil, err
		}
		if rep, err = s.loadReport(p); err != nil {
			return nil, err
		}
	case a.Report == "" && a.Pack != "" && a.Snapshot != "":
		run, err := s.runDrill(drillArgs{Pack: a.Pack, Snapshot: a.Snapshot, Policy: a.Policy, Asset: a.Asset})
		if err != nil {
			return nil, err
		}
		rep = run.rep
		out["report"] = run.report
	default:
		return nil, &argError{"give report, or pack and snapshot (with optional policy and asset)"}
	}
	groups := map[string]*factGroup{}
	needs := 0
	for _, v := range rep.Verdicts {
		if v.State != "needs_review" {
			continue
		}
		needs++
		for _, h := range v.Hints {
			if h.CheckID == "" {
				continue
			}
			info, known := engine.Reasons[h.Reason]
			if !known || info.Kind != engine.KindLeaf {
				continue
			}
			hv := hintView(h)
			var factKey, packHint string
			if hv.Untrusted != nil {
				if hv.Untrusted.Detail != nil {
					factKey = *hv.Untrusted.Detail
				}
				packHint = hv.Untrusted.PackHint
			}
			key := "fact:" + factKey
			if factKey == "" {
				key = "check:" + h.CheckID
			}
			g := groups[key]
			if g == nil {
				g = &factGroup{CheckIDs: []string{}, Reasons: []reasonAction{}, Actors: []string{}, assetSeen: map[string]bool{},
					Untrusted: groupUntrusted{FactKey: factKey, AssetIDs: []string{}}, sortKey: key}
				groups[key] = g
			}
			if hv.CheckID != "" {
				g.CheckIDs = appendUnique(g.CheckIDs, hv.CheckID)
			} else if hv.Untrusted != nil && hv.Untrusted.CheckID != "" && len(g.Untrusted.CheckIDs) < maxUntrustedItems {
				g.Untrusted.CheckIDs = appendUnique(g.Untrusted.CheckIDs, hv.Untrusted.CheckID)
			}
			if !hasReason(g.Reasons, h.Reason) {
				g.Reasons = append(g.Reasons, reasonAction{Reason: h.Reason, Actor: info.Actor, NextAction: info.NextAction, Hint: hv.Hint})
			}
			g.Actors = appendUnique(g.Actors, info.Actor)
			if packHint != "" && len(g.Untrusted.PackHints) < 10 {
				g.Untrusted.PackHints = appendUnique(g.Untrusted.PackHints, packHint)
			}
			if !g.assetSeen[v.AssetID] {
				g.assetSeen[v.AssetID] = true
				g.Assets++
				if len(g.Untrusted.AssetIDs) < maxUntrustedItems {
					g.Untrusted.AssetIDs = append(g.Untrusted.AssetIDs, clean(v.AssetID))
				}
			}
		}
	}
	list := make([]*factGroup, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.CheckIDs)
		sort.Strings(g.Actors)
		sort.Slice(g.Reasons, func(i, j int) bool { return g.Reasons[i].Reason < g.Reasons[j].Reason })
		list = append(list, g)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].sortKey < list[j].sortKey })
	out["needs_review_assets"] = needs
	out["assets_total"] = len(rep.Verdicts)
	out["pack_status"] = enum(packStatuses, rep.PackStatus)
	out["facts"] = list
	out["untrusted"] = reportUntrusted(rep)
	if cveRE.MatchString(rep.CVE) {
		out["cve"] = rep.CVE
	}
	return out, nil
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func hasReason(list []reasonAction, r string) bool {
	for _, x := range list {
		if x.Reason == r {
			return true
		}
	}
	return false
}

// loadReport reads a report with the snapshot size cap and validates it as
// report validate does.
func (s *Server) loadReport(p string) (*engine.Report, error) {
	data, err := readCapped(p, s.cfg.MaxSnapshotBytes)
	if err != nil {
		return nil, &toolError{kind: "input_error", msg: "cannot read the report", detail: err.Error()}
	}
	if err := reportschema.Validate(data); err != nil {
		return nil, &toolError{kind: "input_error", msg: "the report is not valid (schema or reason catalog)", detail: err.Error()}
	}
	var rep engine.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, &toolError{kind: "input_error", msg: "the report is not valid", detail: err.Error()}
	}
	return &rep, nil
}

func readCapped(p string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("file is over the %d-byte cap", max)
	}
	return data, nil
}

// ---- verdict_diff ----

type diffArgs struct {
	Before string `json:"before"`
	After  string `json:"after"`
	FailOn string `json:"fail_on"`
}

type cliDiff struct {
	OK      bool   `json:"ok"`
	FailOn  string `json:"fail_on"`
	Matched int    `json:"matched"`
	diff.Result
}

type changeOut struct {
	Change         string          `json:"change"`
	Class          string          `json:"class"`
	Before         *diffStateOut   `json:"before"`
	After          *diffStateOut   `json:"after"`
	Fields         []string        `json:"fields"`
	ReasonsAdded   []string        `json:"reasons_added"`
	ReasonsRemoved []string        `json:"reasons_removed"`
	Untrusted      changeUntrusted `json:"untrusted"`
}

type changeUntrusted struct {
	AssetID string `json:"asset_id"`
}

type diffStateOut struct {
	State               string   `json:"state"`
	VEXStatus           string   `json:"vex_status"`
	Justification       string   `json:"justification,omitempty"`
	Confidence          string   `json:"confidence"`
	ExposureUncertainty bool     `json:"exposure_uncertainty"`
	Reasons             []string `json:"reasons"`
}

func stateView(a *diff.AssetState) *diffStateOut {
	if a == nil {
		return nil
	}
	return &diffStateOut{
		State: enum(states, a.State), VEXStatus: enum(vexStatuses, a.VEXStatus), Justification: enum(justifications, a.Justification),
		Confidence: enum(confidences, a.Confidence), ExposureUncertainty: a.ExposureUncertainty, Reasons: knownReasons(a.Reasons),
	}
}

// knownReasons keeps catalog codes; report validation already refuses
// others, so nothing is dropped from a valid report.
func knownReasons(in []string) []string {
	out := []string{}
	for _, r := range in {
		if _, ok := engine.Reasons[r]; ok {
			out = append(out, r)
		}
	}
	return out
}

func toolDiff(s *Server, raw json.RawMessage) (any, error) {
	var a diffArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.Before == "" || a.After == "" {
		return nil, &argError{"before and after are required"}
	}
	if a.FailOn == "" {
		a.FailOn = diff.DefaultFailOn
	}
	if !diff.ValidFailOn(a.FailOn) {
		return nil, &argError{"fail_on must be " + diff.FailOnValues}
	}
	b, err := s.file("before", a.Before, s.cfg.MaxSnapshotBytes)
	if err != nil {
		return nil, err
	}
	af, err := s.file("after", a.After, s.cfg.MaxSnapshotBytes)
	if err != nil {
		return nil, err
	}
	body, err := s.cli("diff", "--json", "--fail-on="+a.FailOn, b, af)
	if len(bytes.TrimSpace(body)) == 0 {
		if err == nil {
			err = errors.New("no output")
		}
		return nil, cliFailure(err)
	}
	var d cliDiff
	if jerr := json.Unmarshal(body, &d); jerr != nil {
		return nil, &toolError{kind: "internal_error", msg: "diff output was not JSON"}
	}
	changes := []changeOut{}
	for _, c := range d.Changes {
		changes = append(changes, changeOut{
			Change: c.Kind, Class: c.Class, Before: stateView(c.Before), After: stateView(c.After),
			Fields: c.Fields, ReasonsAdded: knownReasons(c.ReasonsAdded), ReasonsRemoved: knownReasons(c.ReasonsRemoved),
			Untrusted: changeUntrusted{AssetID: clean(c.AssetID)},
		})
	}
	type ctxOut struct {
		Field     string            `json:"field"`
		Untrusted map[string]string `json:"untrusted"`
	}
	ctx := []ctxOut{}
	for _, c := range d.ContextChanges {
		ctx = append(ctx, ctxOut{Field: c.Field, Untrusted: map[string]string{"before": clean(c.Before), "after": clean(c.After)}})
	}
	out := map[string]any{
		"ok": d.OK, "fail_on": d.FailOn, "matched": d.Matched,
		"before_summary": d.BeforeSummary, "after_summary": d.AfterSummary, "counts": d.Counts,
		"context_changes": ctx, "changes": changes,
		"untrusted": map[string]any{"pack_id": clean(d.PackID), "cve": clean(d.CVE), "before": clean(a.Before), "after": clean(a.After)},
	}
	return out, nil
}

// ---- file validators ----

type pathsArgs struct {
	Paths []string `json:"paths"`
}

type cliFile struct {
	File       string `json:"file"`
	OK         bool   `json:"ok"`
	PackID     string `json:"pack_id"`
	PackSHA256 string `json:"pack_sha256"`
	Error      string `json:"error"`
	NoTests    bool   `json:"no_tests"`
	Tests      []struct {
		Name    string `json:"name"`
		AssetID string `json:"asset_id"`
		State   string `json:"state"`
	} `json:"tests"`
}

type cliFiles struct {
	OK    bool      `json:"ok"`
	Files []cliFile `json:"files"`
}

// runFiles runs a --json validator over real paths and reshapes its files.
func (s *Server) runFiles(withSHA, withTests bool, args ...string) (any, error) {
	body, err := s.cli(args...)
	if len(bytes.TrimSpace(body)) == 0 {
		if err == nil {
			err = errors.New("no output")
		}
		return nil, cliFailure(err)
	}
	var res cliFiles
	if jerr := json.Unmarshal(body, &res); jerr != nil {
		return nil, &toolError{kind: "internal_error", msg: "validator output was not JSON"}
	}
	files := []map[string]any{}
	for _, f := range res.Files {
		u := map[string]any{"file": clean(s.rel(f.File))}
		item := map[string]any{"ok": f.OK, "untrusted": u}
		if f.PackID != "" {
			u["pack_id"] = clean(f.PackID)
		}
		if f.Error != "" {
			u["error"] = clean(s.scrub(f.Error))
		}
		if withSHA && sha256RE.MatchString(f.PackSHA256) {
			item["pack_sha256"] = f.PackSHA256
		}
		if withTests {
			item["no_tests"] = f.NoTests
			tests := []map[string]any{}
			for _, t := range f.Tests {
				tests = append(tests, map[string]any{"state": enum(states, t.State), "untrusted": map[string]any{"name": clean(t.Name), "asset_id": clean(t.AssetID)}})
			}
			item["tests"] = tests
		}
		files = append(files, item)
	}
	return map[string]any{"ok": res.OK, "files": files}, nil
}

func toolPackLint(s *Server, raw json.RawMessage) (any, error) {
	var a pathsArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	ps, err := s.paths("paths", a.Paths, pack.MaxBytes)
	if err != nil {
		return nil, err
	}
	return s.runFiles(false, false, append([]string{"pack", "lint", "--json"}, ps...)...)
}

func toolPackHash(s *Server, raw json.RawMessage) (any, error) {
	var a pathsArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	ps, err := s.paths("paths", a.Paths, pack.MaxBytes)
	if err != nil {
		return nil, err
	}
	return s.runFiles(true, false, append([]string{"pack", "hash", "--json"}, ps...)...)
}

func toolPackTest(s *Server, raw json.RawMessage) (any, error) {
	var a pathsArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	ps, err := s.paths("paths", a.Paths, pack.MaxBytes)
	if err != nil {
		return nil, err
	}
	for i, p := range ps {
		if err := s.checkFixtures(p); err != nil {
			return nil, &toolError{kind: "path_outside_root", msg: fmt.Sprintf("paths[%d]: a test fixture the pack names is outside the server root or missing", i), detail: err.Error()}
		}
	}
	return s.runFiles(false, true, append([]string{"pack", "test", "--json", s.snapCap()}, ps...)...)
}

// checkFixtures refuses a pack whose declared test snapshots or policies
// resolve outside the root: pack test reads them relative to the pack file,
// so a pack inside the root could otherwise name /etc/... or ../../.
// A pack that does not load is left to pack test to report.
func (s *Server) checkFixtures(p string) error {
	data, err := readCapped(p, pack.MaxBytes)
	if err != nil {
		return nil
	}
	pk, err := pack.Load(p, data)
	if err != nil {
		return nil
	}
	for _, tc := range pk.Tests {
		for _, f := range []string{tc.Snapshot, tc.Policy} {
			if f == "" {
				continue
			}
			if !filepath.IsAbs(f) {
				f = filepath.Join(filepath.Dir(p), f)
			}
			if _, err := s.resolve(f); err != nil {
				return fmt.Errorf("test %s: %s: %w", tc.Name, s.scrub(f), err)
			}
		}
	}
	return nil
}

func toolReportValidate(s *Server, raw json.RawMessage) (any, error) {
	var a pathsArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	ps, err := s.paths("paths", a.Paths, s.cfg.MaxSnapshotBytes)
	if err != nil {
		return nil, err
	}
	return s.runFiles(false, false, append([]string{"report", "validate", "--json"}, ps...)...)
}

type pathArgs struct {
	Path string `json:"path"`
}

func toolOpenVEXValidate(s *Server, raw json.RawMessage) (any, error) {
	var a pathArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.Path == "" {
		return nil, &argError{"path is required"}
	}
	p, err := s.file("path", a.Path, s.cfg.MaxSnapshotBytes)
	if err != nil {
		return nil, err
	}
	return s.runFiles(false, false, "openvex", "validate", "--json", p)
}

// ---- verdict_list_packs ----

type listArgs struct {
	Dir string `json:"dir"`
}

func toolListPacks(s *Server, raw json.RawMessage) (any, error) {
	var a listArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.Dir == "" {
		a.Dir = "packs"
	}
	dir, err := s.path("dir", a.Dir)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, &toolError{kind: "path_rejected", msg: "dir: not a directory"}
	}
	packs := []map[string]any{}
	truncated := false
	walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && (d.Name() == ".git" || d.Name() == OutDirName) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if len(packs) == maxListedPacks {
			truncated = true
			return filepath.SkipAll
		}
		packs = append(packs, s.packEntry(p))
		return nil
	})
	if walkErr != nil {
		return nil, &toolError{kind: "input_error", msg: "cannot list the directory", detail: walkErr.Error()}
	}
	return map[string]any{"ok": true, "packs": packs, "truncated": truncated}, nil
}

func (s *Server) packEntry(p string) map[string]any {
	u := map[string]any{"file": clean(s.rel(p))}
	item := map[string]any{"ok": false, "untrusted": u}
	real, err := s.resolve(p) // a symlinked file must stay inside the root
	if err != nil {
		u["error"] = clean(err.Error())
		return item
	}
	data, err := readCapped(real, pack.MaxBytes)
	if err != nil {
		u["error"] = clean(s.scrub(err.Error()))
		return item
	}
	pk, err := pack.Load(real, data)
	if err != nil {
		u["error"] = clean(s.scrub(err.Error()))
		return item
	}
	cves := []string{}
	for _, c := range pk.Metadata.CVE {
		if cveRE.MatchString(c) {
			cves = append(cves, c)
		}
	}
	item["ok"] = true
	item["status"] = enum(packStatuses, pk.Metadata.Status)
	item["cve"] = cves
	item["confidence_ceiling"] = enum(confidences, pk.Metadata.ConfidenceCeiling)
	item["synthetic"] = pk.Metadata.Synthetic
	item["reviewers"] = pack.DistinctReviewers(pk)
	item["checks"] = len(pk.Checks)
	item["tests"] = len(pk.Tests)
	u["pack_id"] = clean(pk.Metadata.ID)
	u["title"] = clean(pk.Metadata.Title)
	u["description"] = clean(pk.Metadata.Description)
	return item
}
