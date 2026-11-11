// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// JndiLookupFactKey is the host fact the Log4Shell pack reads.
const JndiLookupFactKey = "jar.class.org.apache.logging.log4j.core.lookup.JndiLookup"

// JDK9FactKey is the host fact the Spring4Shell pack reads.
const JDK9FactKey = "runtime.jdk9_or_newer"

const (
	jndiLookupClass = "org/apache/logging/log4j/core/lookup/JndiLookup.class"
	log4jCorePkg    = "org/apache/logging/log4j/core/"
	log4jGroup      = "org.apache.logging.log4j"
	log4jArtifact   = "log4j-core"
	jarFactSource   = "verdict-import-jar"
)

// JarLimits bound the work done on one import. They apply to the sum of
// every input and every nested archive, except MaxEntryBytes.
type JarLimits struct {
	// MaxDepth is how many archives deep a nested archive may sit.
	// The top-level input is depth 0.
	MaxDepth int
	// MaxEntries counts every central-directory entry in every archive.
	MaxEntries int
	// MaxEntryBytes is the largest uncompressed entry that is read.
	MaxEntryBytes int64
	// MaxTotalBytes is the sum of uncompressed bytes read across the import.
	MaxTotalBytes int64
}

// DefaultJarLimits are sized for real application archives, not for zip bombs.
func DefaultJarLimits() JarLimits {
	return JarLimits{
		MaxDepth:      4,
		MaxEntries:    200000,
		MaxEntryBytes: 64 << 20,
		MaxTotalBytes: 512 << 20,
	}
}

// JarInput is one archive the operator passed. Name is a display label;
// only its base name reaches the snapshot.
type JarInput struct {
	Name string
	Data []byte
}

// JarOptions labels a JAR import. Inventory basis and confidence are fixed
// at observed and high because the archive bytes were read. JavaVersion is
// the operator's statement about the runtime; empty means not stated.
type JarOptions struct {
	AssetID     string
	AssetName   string
	AssetKind   string
	Zones       []string
	Complete    bool
	ObservedAt  string
	KBVersion   string
	Evaluation  string
	JavaVersion string
	Limits      JarLimits
}

// ErrJarLimit marks an archive refused by a size, count, depth, or name rule.
var ErrJarLimit = errors.New("archive refused")

var mavenToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// manifestComponents maps an exact MANIFEST.MF Implementation-Title to Maven
// coordinates. A title outside this table is never guessed.
var manifestComponents = map[string][2]string{
	"Apache Log4j Core": {log4jGroup, log4jArtifact},
	"spring-webmvc":     {"org.springframework", "spring-webmvc"},
	"spring-webflux":    {"org.springframework", "spring-webflux"},
	"spring-beans":      {"org.springframework", "spring-beans"},
}

type coord struct {
	group, artifact, version, where string
}

// archiveScan is what one archive (not its children) contained.
type archiveScan struct {
	where      string
	sum        string
	poms       []coord
	pomErrs    []string
	manifest   *coord
	jndiPath   string
	coreClass  bool
	identified bool // carries log4j-core coordinates
}

type jarScanner struct {
	lim     JarLimits
	entries int
	total   int64
	scans   []*archiveScan
	skipped []string
}

// Jar inspects JAR, WAR, and EAR files in memory and builds one asset.
// Nothing is written to disk and nothing is fetched. A component without
// pom.properties, or an unambiguous manifest, is skipped instead of guessed.
func Jar(inputs []JarInput, opt JarOptions) (*Result, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("import jar: at least one input is required")
	}
	if opt.AssetID == "" || opt.AssetName == "" {
		return nil, fmt.Errorf("import: asset id and name are required")
	}
	if opt.KBVersion == "" || opt.Evaluation == "" || opt.ObservedAt == "" {
		return nil, fmt.Errorf("import: kb version, evaluation time, and observed time are required")
	}
	if opt.AssetKind == "" {
		opt.AssetKind = "app"
	}
	if opt.Limits == (JarLimits{}) {
		opt.Limits = DefaultJarLimits()
	}
	var jdk9 string
	if opt.JavaVersion != "" {
		major, err := JavaMajor(opt.JavaVersion)
		if err != nil {
			return nil, fmt.Errorf("import jar: %w", err)
		}
		jdk9 = strconv.FormatBool(major >= 9)
	}

	sc := &jarScanner{lim: opt.Limits}
	inv := sha256.New()
	for _, in := range inputs {
		label := path.Base(strings.ReplaceAll(in.Name, "\\", "/"))
		if int64(len(in.Data)) > sc.lim.MaxTotalBytes {
			return nil, fmt.Errorf("import jar: %s: %w: input exceeds %d bytes", label, ErrJarLimit, sc.lim.MaxTotalBytes)
		}
		sum := sha256.Sum256(in.Data)
		inv.Write(sum[:])
		if err := sc.scan(in.Data, label, 0); err != nil {
			return nil, fmt.Errorf("import jar: %w", err)
		}
	}

	pkgs, skipped := sc.packages()
	fact, notes := sc.jndiFact(opt.ObservedAt)
	if opt.Complete && len(skipped) > 0 {
		return nil, fmt.Errorf("import jar: inventory cannot be complete: %d components skipped (%s)", len(skipped), strings.Join(skipped, "; "))
	}
	facts := []snapshot.Fact{}
	if fact != nil {
		facts = append(facts, *fact)
	}
	if jdk9 != "" {
		facts = append(facts, snapshot.Fact{
			Key: JDK9FactKey, Value: jdk9, Basis: "attested", Confidence: "high",
			ObservedAt: opt.ObservedAt, EvidenceID: "e-java-version-" + shortHash([]byte(opt.JavaVersion)),
			Source: "operator --java-version " + opt.JavaVersion,
		})
	} else {
		notes = append(notes, JDK9FactKey+" omitted: --java-version was not given and class file versions are not a runtime")
	}
	if len(pkgs) == 0 && fact == nil {
		return nil, fmt.Errorf("import jar: no component identified and no Log4j class observed (%s)", strings.Join(skipped, "; "))
	}
	zones := opt.Zones
	if zones == nil {
		zones = []string{}
	}
	snap := &snapshot.Snapshot{
		KBVersion:      opt.KBVersion,
		EvaluationTime: opt.Evaluation,
		EvidenceTrust:  "caller_asserted",
		Assets: []snapshot.Asset{{
			ID: opt.AssetID, Name: opt.AssetName, Kind: opt.AssetKind, Zones: zones,
			Inventory: snapshot.Inventory{
				Complete:   opt.Complete,
				ObservedAt: opt.ObservedAt,
				Basis:      "observed",
				Confidence: "high",
				EvidenceID: "e-jar-" + hex.EncodeToString(inv.Sum(nil))[:32],
				Packages:   pkgs,
			},
			Facts:    facts,
			Exposure: []snapshot.Exposure{},
		}},
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	checked, err := snapshot.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("import jar: %w", err)
	}
	return &Result{Snapshot: checked, Skipped: skipped, Notes: notes}, nil
}

// JavaMajor reads the feature release from a java.version string such as
// 1.8.0_292, 11, 17.0.2, or 21-ea.
func JavaMajor(v string) (int, error) {
	s := strings.TrimSpace(v)
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '_' || r == '-' || r == '+' })
	if len(parts) == 0 {
		return 0, fmt.Errorf("java version %q is not recognized", v)
	}
	first, err := strconv.Atoi(parts[0])
	if err != nil || first < 1 {
		return 0, fmt.Errorf("java version %q is not recognized", v)
	}
	if first == 1 {
		if len(parts) < 2 {
			return 0, fmt.Errorf("java version %q is not recognized", v)
		}
		second, err := strconv.Atoi(parts[1])
		if err != nil || second < 1 || second > 8 {
			return 0, fmt.Errorf("java version %q is not recognized", v)
		}
		return second, nil
	}
	if first > 99 {
		return 0, fmt.Errorf("java version %q is not recognized", v)
	}
	return first, nil
}

func (sc *jarScanner) scan(data []byte, where string, depth int) error {
	if depth > sc.lim.MaxDepth {
		return fmt.Errorf("%s: %w: nesting depth exceeds %d", where, ErrJarLimit, sc.lim.MaxDepth)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return fmt.Errorf("%s: not a readable zip archive: %w", where, err)
	}
	if zr == nil {
		return fmt.Errorf("%s: not a readable zip archive", where)
	}
	sc.entries += len(zr.File)
	if sc.entries > sc.lim.MaxEntries {
		return fmt.Errorf("%s: %w: more than %d entries", where, ErrJarLimit, sc.lim.MaxEntries)
	}
	// Names are checked before anything is read, so one bad name refuses the whole archive.
	for _, f := range zr.File {
		if err := checkEntryName(f.Name); err != nil {
			return fmt.Errorf("%s: %w: %v", where, ErrJarLimit, err)
		}
	}
	sum := sha256.Sum256(data)
	as := &archiveScan{where: where, sum: hex.EncodeToString(sum[:])}
	sc.scans = append(sc.scans, as)

	type nested struct {
		f    *zip.File
		name string
	}
	var children []nested
	for _, f := range zr.File {
		name := f.Name
		if strings.HasSuffix(name, "/") {
			continue
		}
		switch {
		case name == jndiLookupClass || strings.HasSuffix(name, "/"+jndiLookupClass):
			if as.jndiPath == "" {
				as.jndiPath = name
			}
			as.coreClass = true
		case strings.HasSuffix(name, ".class") && (strings.HasPrefix(name, log4jCorePkg) || strings.Contains(name, "/"+log4jCorePkg)):
			as.coreClass = true
		case name == "META-INF/MANIFEST.MF":
			body, err := sc.read(f, where)
			if err != nil {
				return err
			}
			as.manifest = manifestCoord(body, where+"!/"+name)
		case isPomProperties(name):
			body, err := sc.read(f, where)
			if err != nil {
				return err
			}
			c, perr := pomCoord(name, body)
			if perr != nil {
				as.pomErrs = append(as.pomErrs, where+"!/"+name+": "+perr.Error())
				continue
			}
			c.where = where + "!/" + name
			as.poms = append(as.poms, c)
		case isNestedArchive(name):
			children = append(children, nested{f: f, name: name})
		}
	}
	for _, c := range as.poms {
		if c.group == log4jGroup && c.artifact == log4jArtifact {
			as.identified = true
		}
	}
	if len(as.poms) == 0 && len(as.pomErrs) == 0 && as.manifest != nil &&
		as.manifest.group == log4jGroup && as.manifest.artifact == log4jArtifact {
		as.identified = true
	}
	for _, ch := range children {
		body, err := sc.read(ch.f, where)
		if err != nil {
			return err
		}
		if err := sc.scan(body, where+"!/"+ch.name, depth+1); err != nil {
			if errors.Is(err, ErrJarLimit) {
				return err
			}
			sc.skipped = append(sc.skipped, err.Error())
		}
	}
	return nil
}

// read returns one entry, bounded by the per-entry and total caps. The
// declared size is checked first and the actual stream is capped too,
// because a crafted header can understate it.
func (sc *jarScanner) read(f *zip.File, where string) ([]byte, error) {
	if f.UncompressedSize64 > uint64(sc.lim.MaxEntryBytes) {
		return nil, fmt.Errorf("%s!/%s: %w: entry declares %d bytes, limit %d", where, f.Name, ErrJarLimit, f.UncompressedSize64, sc.lim.MaxEntryBytes)
	}
	if sc.total+int64(f.UncompressedSize64) > sc.lim.MaxTotalBytes {
		return nil, fmt.Errorf("%s!/%s: %w: total uncompressed bytes exceed %d", where, f.Name, ErrJarLimit, sc.lim.MaxTotalBytes)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("%s!/%s: %w", where, f.Name, err)
	}
	defer rc.Close()
	body, err := io.ReadAll(io.LimitReader(rc, sc.lim.MaxEntryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s!/%s: %w", where, f.Name, err)
	}
	if int64(len(body)) > sc.lim.MaxEntryBytes {
		return nil, fmt.Errorf("%s!/%s: %w: entry inflates past %d bytes", where, f.Name, ErrJarLimit, sc.lim.MaxEntryBytes)
	}
	sc.total += int64(len(body))
	if sc.total > sc.lim.MaxTotalBytes {
		return nil, fmt.Errorf("%s!/%s: %w: total uncompressed bytes exceed %d", where, f.Name, ErrJarLimit, sc.lim.MaxTotalBytes)
	}
	return body, nil
}

func checkEntryName(name string) error {
	if name == "" || strings.ContainsRune(name, 0) || strings.Contains(name, "\\") ||
		strings.HasPrefix(name, "/") || (len(name) >= 2 && name[1] == ':') {
		return fmt.Errorf("entry name %q is not a safe relative path", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return fmt.Errorf("entry name %q traverses upward", name)
		}
	}
	return nil
}

func isNestedArchive(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war") || strings.HasSuffix(lower, ".ear")
}

func isPomProperties(name string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 5 && parts[0] == "META-INF" && parts[1] == "maven" && parts[4] == "pom.properties"
}

func pomCoord(name string, body []byte) (coord, error) {
	parts := strings.Split(name, "/")
	props := parseProperties(body)
	c := coord{group: props["groupId"], artifact: props["artifactId"], version: props["version"]}
	if c.group == "" || c.artifact == "" || c.version == "" {
		return coord{}, fmt.Errorf("groupId, artifactId, or version is missing")
	}
	if c.group != parts[2] || c.artifact != parts[3] {
		return coord{}, fmt.Errorf("coordinates %s:%s do not match the directory %s/%s", c.group, c.artifact, parts[2], parts[3])
	}
	if !mavenToken.MatchString(c.group) || !mavenToken.MatchString(c.artifact) || !mavenToken.MatchString(c.version) {
		return coord{}, fmt.Errorf("coordinates %s:%s:%s contain unsupported characters", c.group, c.artifact, c.version)
	}
	return c, nil
}

// parseProperties reads the subset of java.util.Properties that Maven writes.
// Line continuations and escapes are not interpreted; a value that needs
// them fails the token check and is skipped.
func parseProperties(body []byte) map[string]string {
	out := map[string]string{}
	s := bufio.NewScanner(bytes.NewReader(body))
	s.Buffer(make([]byte, 0, 4096), 64<<10)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		i := strings.IndexAny(line, "=:")
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		if _, dup := out[key]; dup {
			out[key] = "" // two values for one key is ambiguous
			continue
		}
		out[key] = strings.TrimSpace(line[i+1:])
	}
	return out
}

// manifestCoord maps a manifest only when the title is in the fixed table
// and the version is a plain token.
func manifestCoord(body []byte, where string) *coord {
	attrs := map[string]string{}
	s := bufio.NewScanner(bytes.NewReader(body))
	s.Buffer(make([]byte, 0, 4096), 64<<10)
	for s.Scan() {
		line := strings.TrimRight(s.Text(), "\r")
		if line == "" {
			break // main section only
		}
		if strings.HasPrefix(line, " ") {
			continue // continuation lines are not needed for the two keys used
		}
		i := strings.Index(line, ": ")
		if i < 0 {
			continue
		}
		attrs[line[:i]] = strings.TrimSpace(line[i+2:])
	}
	ga, ok := manifestComponents[attrs["Implementation-Title"]]
	ver := attrs["Implementation-Version"]
	if !ok || !mavenToken.MatchString(ver) {
		return nil
	}
	return &coord{group: ga[0], artifact: ga[1], version: ver, where: where}
}

func (sc *jarScanner) packages() ([]snapshot.Package, []string) {
	skipped := append([]string{}, sc.skipped...)
	byPURL := map[string]snapshot.Package{}
	for _, as := range sc.scans {
		skipped = append(skipped, as.pomErrs...)
		coords := as.poms
		if len(coords) == 0 && len(as.pomErrs) == 0 {
			if as.manifest != nil {
				coords = []coord{*as.manifest}
			} else {
				skipped = append(skipped, as.where+": no pom.properties and the manifest does not name a known component")
			}
		}
		for _, c := range coords {
			pkg, err := packageFromPURL("pkg:maven/"+c.group+"/"+c.artifact+"@"+c.version, "")
			if err != nil {
				skipped = append(skipped, c.where+": "+err.Error())
				continue
			}
			byPURL[pkg.PURL] = pkg
		}
		if as.jndiPath != "" && !as.identified {
			skipped = append(skipped, as.where+": log4j-core classes ("+as.jndiPath+") without log4j-core pom.properties; version unknown, package not recorded")
		} else if as.coreClass && !as.identified {
			skipped = append(skipped, as.where+": log4j-core classes without log4j-core pom.properties; version unknown, package not recorded")
		}
	}
	pkgs := make([]snapshot.Package, 0, len(byPURL))
	for _, p := range byPURL {
		pkgs = append(pkgs, p)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].PURL < pkgs[j].PURL })
	sort.Strings(skipped)
	return pkgs, skipped
}

// jndiFact applies the Log4Shell class rule:
// present if the class is in any scanned archive; absent only if every
// identified log4j-core copy holds other log4j-core classes but not this
// one and no unidentified log4j-core classes were seen; otherwise omitted.
func (sc *jarScanner) jndiFact(observedAt string) (*snapshot.Fact, []string) {
	mk := func(value string, as *archiveScan, inner string) *snapshot.Fact {
		return &snapshot.Fact{
			Key: JndiLookupFactKey, Value: value, Basis: "observed", Confidence: "high",
			ObservedAt: observedAt, EvidenceID: "e-jar-" + shortHash([]byte(as.sum+"\x00"+inner)),
			Source: jarFactSource + " " + as.where,
		}
	}
	for _, as := range sc.scans {
		if as.jndiPath != "" {
			return mk("present", as, as.jndiPath), nil
		}
	}
	var copies []*archiveScan
	for _, as := range sc.scans {
		if as.identified {
			copies = append(copies, as)
			continue
		}
		if as.coreClass {
			return nil, []string{JndiLookupFactKey + " omitted: " + as.where + " has log4j-core classes without coordinates, so a relocated JndiLookup cannot be ruled out"}
		}
	}
	if len(copies) == 0 {
		return nil, nil
	}
	for _, as := range copies {
		if !as.coreClass {
			return nil, []string{JndiLookupFactKey + " omitted: " + as.where + " names log4j-core but holds no log4j-core classes, so the class may live elsewhere"}
		}
	}
	return mk("absent", copies[0], "absent:"+jndiLookupClass), nil
}

func shortHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:32]
}
