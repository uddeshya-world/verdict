// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/uddeshya-world/verdict/internal/purl"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// MaxK8sInputBytes is the largest single kubectl JSON file accepted.
const MaxK8sInputBytes = 64 * 1024 * 1024

// ZoneClusterInternal is the zone written for ClusterIP Services and the pod
// network. The operator classifies it in the site policy. It is not trusted
// by default: a zone in neither policy list is treated as exposed.
const ZoneClusterInternal = "cluster-internal"

// ZoneUnknown is written when no flag names the zone for a Service type.
// The engine treats it as exposed.
const ZoneUnknown = "unknown"

// IngressNginxAdmissionFact is the fact key the ingress-nginx pack reads.
const IngressNginxAdmissionFact = "ingress_nginx.admission_webhook"

// IngressNginxPURLBase is the app package URL the ingress-nginx pack matches.
const IngressNginxPURLBase = "pkg:generic/ingress-nginx"

// K8sInput is one local kubectl JSON file.
type K8sInput struct {
	Name string
	Data []byte
}

// K8sOptions labels a Kubernetes import. Zones left empty become "unknown".
type K8sOptions struct {
	Cluster          string
	KBVersion        string
	Evaluation       string
	ObservedAt       string
	LoadBalancerZone string
	NodePortZone     string
	IngressZone      string
}

const k8sSource = "kubectl-json"

var (
	clusterRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	cleanVersionRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	digestRE       = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// Upstream ingress-nginx controller images. A mirror or rebuild is not
// recognized: its tag is the mirror operator's claim, not the upstream release.
var ingressNginxImages = map[string]struct{}{
	"registry.k8s.io/ingress-nginx/controller":        {},
	"registry.k8s.io/ingress-nginx/controller-chroot": {},
	"k8s.gcr.io/ingress-nginx/controller":             {},
	"k8s.gcr.io/ingress-nginx/controller-chroot":      {},
}

type k8sMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Labels          map[string]string `json:"labels"`
	OwnerReferences []struct {
		Kind       string `json:"kind"`
		Name       string `json:"name"`
		Controller *bool  `json:"controller"`
	} `json:"ownerReferences"`
}

type k8sObject struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   k8sMeta           `json:"metadata"`
	Spec       json.RawMessage   `json:"spec"`
	Items      []json.RawMessage `json:"items"`
	Webhooks   []k8sWebhook      `json:"webhooks"`

	file string
}

type k8sWebhook struct {
	Name         string `json:"name"`
	ClientConfig struct {
		URL     *string `json:"url"`
		Service *struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			Port      *int   `json:"port"`
		} `json:"service"`
	} `json:"clientConfig"`
}

type k8sContainerPort struct {
	Name          string `json:"name"`
	ContainerPort int    `json:"containerPort"`
	HostPort      int    `json:"hostPort"`
	Protocol      string `json:"protocol"`
}

type k8sContainer struct {
	Name    string             `json:"name"`
	Image   string             `json:"image"`
	Command []string           `json:"command"`
	Args    []string           `json:"args"`
	Ports   []k8sContainerPort `json:"ports"`
}

type k8sPodSpec struct {
	Containers     []k8sContainer `json:"containers"`
	InitContainers []k8sContainer `json:"initContainers"`
	HostNetwork    bool           `json:"hostNetwork"`
}

type k8sWorkloadSpec struct {
	Template *struct {
		Metadata k8sMeta    `json:"metadata"`
		Spec     k8sPodSpec `json:"spec"`
	} `json:"template"`
}

// intOrString is a Kubernetes IntOrString. Zero value means unset.
type intOrString struct {
	set bool
	num int
	str string
}

func (v *intOrString) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		if err := json.Unmarshal(b, &v.str); err != nil {
			return err
		}
		v.set = true
		if n, err := strconv.Atoi(v.str); err == nil {
			v.num, v.str = n, ""
		}
		return nil
	}
	if err := json.Unmarshal(b, &v.num); err != nil {
		return fmt.Errorf("targetPort must be a number or a name")
	}
	v.set = true
	return nil
}

type k8sServicePort struct {
	Name       string      `json:"name"`
	Port       int         `json:"port"`
	TargetPort intOrString `json:"targetPort"`
	Protocol   string      `json:"protocol"`
}

type k8sServiceSpec struct {
	Type        string            `json:"type"`
	Selector    map[string]string `json:"selector"`
	ExternalIPs []string          `json:"externalIPs"`
	Ports       []k8sServicePort  `json:"ports"`
}

type k8sBackend struct {
	Service *struct {
		Name string `json:"name"`
		Port struct {
			Number int    `json:"number"`
			Name   string `json:"name"`
		} `json:"port"`
	} `json:"service"`
}

type k8sIngressSpec struct {
	DefaultBackend *k8sBackend `json:"defaultBackend"`
	Rules          []struct {
		HTTP *struct {
			Paths []struct {
				Backend k8sBackend `json:"backend"`
			} `json:"paths"`
		} `json:"http"`
	} `json:"rules"`
}

type k8sWorkload struct {
	Namespace string
	Kind      string
	Name      string
	labelSets []map[string]string
	specs     []k8sPodSpec
}

func (w *k8sWorkload) key() string { return w.Namespace + "/" + w.Kind + "/" + w.Name }

type k8sService struct {
	Namespace string
	Name      string
	Spec      k8sServiceSpec
}

type k8sCluster struct {
	workloads   map[string]*k8sWorkload
	services    map[string]*k8sService // ns/name
	ingresses   []k8sObject
	webhooks    []k8sObject
	sawWebhooks bool
	ignored     map[string]int
	notes       []string
}

// Kubernetes reads kubectl JSON (a List or single objects, one or more files)
// into one snapshot asset per workload. It reads only the bytes it is given.
// NetworkPolicy objects are not used to narrow exposure.
func Kubernetes(inputs []K8sInput, opt K8sOptions) (*Result, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("import k8s: at least one input is required")
	}
	if !clusterRE.MatchString(opt.Cluster) {
		return nil, fmt.Errorf("import k8s: cluster name %q is invalid", opt.Cluster)
	}
	if opt.KBVersion == "" || opt.Evaluation == "" || opt.ObservedAt == "" {
		return nil, fmt.Errorf("import k8s: kb version, evaluation time, and observed time are required")
	}
	var objs []k8sObject
	for _, in := range inputs {
		got, err := decodeK8sFile(in)
		if err != nil {
			return nil, err
		}
		objs = append(objs, got...)
	}
	c, err := indexK8s(objs)
	if err != nil {
		return nil, err
	}
	if len(c.workloads) == 0 {
		return nil, fmt.Errorf("import k8s: no Deployment, DaemonSet, StatefulSet, or Pod objects in input")
	}
	exposures, err := c.exposures(opt)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(c.workloads))
	for k := range c.workloads {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	snap := &snapshot.Snapshot{
		KBVersion:      opt.KBVersion,
		EvaluationTime: opt.Evaluation,
		EvidenceTrust:  "caller_asserted",
	}
	for _, k := range keys {
		w := c.workloads[k]
		asset, err := c.asset(w, opt, exposures[k])
		if err != nil {
			return nil, err
		}
		snap.Assets = append(snap.Assets, asset)
	}
	sort.Slice(snap.Assets, func(i, j int) bool { return snap.Assets[i].ID < snap.Assets[j].ID })

	ignoredKinds := make([]string, 0, len(c.ignored))
	for k := range c.ignored {
		ignoredKinds = append(ignoredKinds, k)
	}
	sort.Strings(ignoredKinds)
	skipped := []string{}
	for _, k := range ignoredKinds {
		msg := fmt.Sprintf("%s: %d object(s) not imported", k, c.ignored[k])
		if k == "NetworkPolicy" {
			msg += "; NetworkPolicy is not used to narrow exposure"
		}
		skipped = append(skipped, msg)
	}
	skipped = append(skipped, c.notes...)

	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	checked, err := snapshot.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("import k8s: %w", err)
	}
	return &Result{Snapshot: checked, Skipped: skipped}, nil
}

func decodeK8sFile(in K8sInput) ([]k8sObject, error) {
	where := "import k8s: " + in.Name
	if len(in.Data) == 0 {
		return nil, fmt.Errorf("%s: empty document", where)
	}
	if len(in.Data) > MaxK8sInputBytes {
		return nil, fmt.Errorf("%s: exceeds %d bytes", where, MaxK8sInputBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(in.Data))
	var top k8sObject
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: trailing JSON", where)
	}
	if top.Kind == "" {
		return nil, fmt.Errorf("%s: kind is missing; expected kubectl -o json output", where)
	}
	if !strings.HasSuffix(top.Kind, "List") {
		top.file = in.Name
		if err := checkK8sObject(top); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		return []k8sObject{top}, nil
	}
	if top.Items == nil {
		return nil, fmt.Errorf("%s: %s has no items array", where, top.Kind)
	}
	out := make([]k8sObject, 0, len(top.Items))
	for i, raw := range top.Items {
		var o k8sObject
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, fmt.Errorf("%s: items[%d]: %w", where, i, err)
		}
		if strings.HasSuffix(o.Kind, "List") {
			return nil, fmt.Errorf("%s: items[%d]: nested %s is not supported", where, i, o.Kind)
		}
		o.file = in.Name
		if err := checkK8sObject(o); err != nil {
			return nil, fmt.Errorf("%s: items[%d]: %w", where, i, err)
		}
		out = append(out, o)
	}
	return out, nil
}

func checkK8sObject(o k8sObject) error {
	if o.APIVersion == "" || o.Kind == "" || o.Metadata.Name == "" {
		return fmt.Errorf("object needs apiVersion, kind, and metadata.name")
	}
	switch o.Kind {
	case "Deployment", "DaemonSet", "StatefulSet", "Pod", "Service", "Ingress":
		if o.Metadata.Namespace == "" {
			return fmt.Errorf("%s %s has no metadata.namespace", o.Kind, o.Metadata.Name)
		}
		if len(o.Spec) == 0 || string(o.Spec) == "null" {
			return fmt.Errorf("%s %s/%s has no spec", o.Kind, o.Metadata.Namespace, o.Metadata.Name)
		}
	}
	return nil
}

func indexK8s(objs []k8sObject) (*k8sCluster, error) {
	c := &k8sCluster{
		workloads: map[string]*k8sWorkload{},
		services:  map[string]*k8sService{},
		ignored:   map[string]int{},
	}
	seen := map[string]string{}
	var pods []k8sObject
	for _, o := range objs {
		id := o.Kind + "/" + o.Metadata.Namespace + "/" + o.Metadata.Name
		if prev, ok := seen[id]; ok {
			return nil, fmt.Errorf("import k8s: %s appears in both %s and %s", id, prev, o.file)
		}
		seen[id] = o.file
		where := fmt.Sprintf("import k8s: %s: %s %s/%s", o.file, o.Kind, o.Metadata.Namespace, o.Metadata.Name)
		switch o.Kind {
		case "Deployment", "DaemonSet", "StatefulSet":
			var spec k8sWorkloadSpec
			if err := json.Unmarshal(o.Spec, &spec); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			if spec.Template == nil {
				return nil, fmt.Errorf("%s: spec.template is missing", where)
			}
			if err := checkPodSpec(spec.Template.Spec); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			w := &k8sWorkload{Namespace: o.Metadata.Namespace, Kind: o.Kind, Name: o.Metadata.Name}
			w.labelSets = append(w.labelSets, spec.Template.Metadata.Labels)
			w.specs = append(w.specs, spec.Template.Spec)
			c.workloads[w.key()] = w
		case "Pod":
			pods = append(pods, o)
		case "Service":
			var spec k8sServiceSpec
			if err := json.Unmarshal(o.Spec, &spec); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			for _, p := range spec.Ports {
				if p.Port < 1 || p.Port > 65535 {
					return nil, fmt.Errorf("%s: service port %d is invalid", where, p.Port)
				}
				if p.TargetPort.set && p.TargetPort.str == "" && (p.TargetPort.num < 1 || p.TargetPort.num > 65535) {
					return nil, fmt.Errorf("%s: targetPort %d is invalid", where, p.TargetPort.num)
				}
			}
			c.services[o.Metadata.Namespace+"/"+o.Metadata.Name] = &k8sService{
				Namespace: o.Metadata.Namespace, Name: o.Metadata.Name, Spec: spec,
			}
		case "Ingress":
			var spec k8sIngressSpec
			if err := json.Unmarshal(o.Spec, &spec); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			c.ingresses = append(c.ingresses, o)
		case "ValidatingWebhookConfiguration":
			c.sawWebhooks = true
			c.webhooks = append(c.webhooks, o)
		default:
			c.ignored[o.Kind]++
		}
	}
	// Pods fold into their owning workload when it is in the input, so the
	// images actually scheduled are counted. Otherwise a Pod is its own asset.
	for _, o := range pods {
		var spec k8sPodSpec
		where := fmt.Sprintf("import k8s: %s: Pod %s/%s", o.file, o.Metadata.Namespace, o.Metadata.Name)
		if err := json.Unmarshal(o.Spec, &spec); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		if err := checkPodSpec(spec); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		w := c.workloads[podOwnerKey(o)]
		if w == nil {
			w = &k8sWorkload{Namespace: o.Metadata.Namespace, Kind: "Pod", Name: o.Metadata.Name}
			c.workloads[w.key()] = w
		}
		w.labelSets = append(w.labelSets, o.Metadata.Labels)
		w.specs = append(w.specs, spec)
	}
	return c, nil
}

func checkPodSpec(s k8sPodSpec) error {
	if len(s.Containers) == 0 {
		return fmt.Errorf("pod spec has no containers")
	}
	for _, list := range [][]k8sContainer{s.InitContainers, s.Containers} {
		for _, ctr := range list {
			if strings.TrimSpace(ctr.Image) == "" {
				return fmt.Errorf("container %q has no image", ctr.Name)
			}
			for _, p := range ctr.Ports {
				if p.ContainerPort < 1 || p.ContainerPort > 65535 {
					return fmt.Errorf("container %q port %d is invalid", ctr.Name, p.ContainerPort)
				}
			}
		}
	}
	return nil
}

// podOwnerKey names the workload that controls a Pod. A ReplicaSet is
// mapped to its Deployment through the pod-template-hash label.
func podOwnerKey(o k8sObject) string {
	for _, ref := range o.Metadata.OwnerReferences {
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		switch ref.Kind {
		case "DaemonSet", "StatefulSet":
			return o.Metadata.Namespace + "/" + ref.Kind + "/" + ref.Name
		case "ReplicaSet":
			hash := o.Metadata.Labels["pod-template-hash"]
			if hash != "" && strings.HasSuffix(ref.Name, "-"+hash) {
				return o.Metadata.Namespace + "/Deployment/" + strings.TrimSuffix(ref.Name, "-"+hash)
			}
		}
	}
	return ""
}

// selectorMatches is Service selector semantics: every key must be present
// with the same value. An empty selector selects nothing here, because such
// a Service's endpoints are managed outside the selector.
func selectorMatches(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		got, ok := labels[k]
		if !ok || got != v {
			return false
		}
	}
	return true
}

func (c *k8sCluster) selects(s *k8sService, w *k8sWorkload) bool {
	if s.Namespace != w.Namespace {
		return false
	}
	for _, labels := range w.labelSets {
		if selectorMatches(s.Spec.Selector, labels) {
			return true
		}
	}
	return false
}

func zoneOr(z string) string {
	if strings.TrimSpace(z) == "" {
		return ZoneUnknown
	}
	return z
}

type exposureKey struct {
	port   int
	proto  string
	source string
}

type exposureSet map[exposureKey]map[string]struct{}

func (e exposureSet) add(port int, proto, source string, zones ...string) {
	k := exposureKey{port: port, proto: proto, source: source}
	if e[k] == nil {
		e[k] = map[string]struct{}{}
	}
	for _, z := range zones {
		e[k][z] = struct{}{}
	}
}

func k8sProto(p string) (string, bool) {
	switch p {
	case "", "TCP":
		return "tcp", true
	case "UDP":
		return "udp", true
	}
	return "", false
}

// targetPorts resolves a Service port to container ports on one workload.
func targetPorts(sp k8sServicePort, w *k8sWorkload) []int {
	if !sp.TargetPort.set {
		return []int{sp.Port}
	}
	if sp.TargetPort.str == "" {
		return []int{sp.TargetPort.num}
	}
	found := map[int]struct{}{}
	for _, spec := range w.specs {
		for _, ctr := range spec.Containers {
			for _, p := range ctr.Ports {
				if p.Name == sp.TargetPort.str && protoOrTCP(p.Protocol) == protoOrTCP(sp.Protocol) {
					found[p.ContainerPort] = struct{}{}
				}
			}
		}
	}
	out := make([]int, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func protoOrTCP(p string) string {
	if p == "" {
		return "TCP"
	}
	return p
}

func (c *k8sCluster) note(format string, args ...any) {
	c.notes = append(c.notes, fmt.Sprintf(format, args...))
}

// serviceZones lists where a Service's ports are reachable from.
// Each wider type also includes the narrower ones it implies.
func serviceZones(s *k8sService, opt K8sOptions) []string {
	zones := []string{ZoneClusterInternal}
	switch s.Spec.Type {
	case "NodePort":
		zones = append(zones, zoneOr(opt.NodePortZone))
	case "LoadBalancer":
		zones = append(zones, zoneOr(opt.LoadBalancerZone), zoneOr(opt.NodePortZone))
	}
	if len(s.Spec.ExternalIPs) > 0 {
		zones = append(zones, zoneOr(opt.LoadBalancerZone))
	}
	return zones
}

func (c *k8sCluster) serviceToWorkloads(s *k8sService, sp k8sServicePort, source string, out map[string]exposureSet, zones []string) {
	proto, ok := k8sProto(sp.Protocol)
	if !ok {
		c.note("Service %s/%s port %d: protocol %s not imported", s.Namespace, s.Name, sp.Port, sp.Protocol)
		return
	}
	keys := sortedWorkloadKeys(c.workloads)
	for _, k := range keys {
		w := c.workloads[k]
		if !c.selects(s, w) {
			continue
		}
		ports := targetPorts(sp, w)
		if len(ports) == 0 {
			c.note("Service %s/%s port %d: named targetPort %q not found on %s; no exposure recorded (stays unknown)", s.Namespace, s.Name, sp.Port, sp.TargetPort.str, w.key())
			continue
		}
		if out[k] == nil {
			out[k] = exposureSet{}
		}
		for _, p := range ports {
			out[k].add(p, proto, source, zones...)
		}
	}
}

func sortedWorkloadKeys(m map[string]*k8sWorkload) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// exposures derives reachability per workload. It only ever adds zones.
// NetworkPolicy is never consulted, so nothing here narrows exposure.
func (c *k8sCluster) exposures(opt K8sOptions) (map[string]exposureSet, error) {
	out := map[string]exposureSet{}
	svcKeys := make([]string, 0, len(c.services))
	for k := range c.services {
		svcKeys = append(svcKeys, k)
	}
	sort.Strings(svcKeys)
	for _, k := range svcKeys {
		s := c.services[k]
		if s.Spec.Type == "ExternalName" {
			continue
		}
		zones := serviceZones(s, opt)
		for _, sp := range s.Spec.Ports {
			c.serviceToWorkloads(s, sp, "kubectl:service/"+s.Namespace+"/"+s.Name, out, zones)
		}
	}
	for _, ing := range c.ingresses {
		var spec k8sIngressSpec
		if err := json.Unmarshal(ing.Spec, &spec); err != nil {
			return nil, fmt.Errorf("import k8s: Ingress %s/%s: %w", ing.Metadata.Namespace, ing.Metadata.Name, err)
		}
		var backends []k8sBackend
		if spec.DefaultBackend != nil {
			backends = append(backends, *spec.DefaultBackend)
		}
		for _, r := range spec.Rules {
			if r.HTTP == nil {
				continue
			}
			for _, p := range r.HTTP.Paths {
				backends = append(backends, p.Backend)
			}
		}
		source := "kubectl:ingress/" + ing.Metadata.Namespace + "/" + ing.Metadata.Name
		for _, b := range backends {
			if b.Service == nil || b.Service.Name == "" {
				c.note("Ingress %s/%s: backend without a service is not imported", ing.Metadata.Namespace, ing.Metadata.Name)
				continue
			}
			s := c.services[ing.Metadata.Namespace+"/"+b.Service.Name]
			if s == nil {
				c.note("Ingress %s/%s: backend Service %s is not in the input", ing.Metadata.Namespace, ing.Metadata.Name, b.Service.Name)
				continue
			}
			matched := false
			for _, sp := range s.Spec.Ports {
				if (b.Service.Port.Number != 0 && sp.Port == b.Service.Port.Number) ||
					(b.Service.Port.Name != "" && sp.Name == b.Service.Port.Name) {
					matched = true
					c.serviceToWorkloads(s, sp, source, out, []string{zoneOr(opt.IngressZone)})
				}
			}
			if !matched {
				c.note("Ingress %s/%s: backend port on Service %s not found", ing.Metadata.Namespace, ing.Metadata.Name, b.Service.Name)
			}
		}
	}
	// Any declared container port is reachable over the pod network unless a
	// NetworkPolicy says otherwise, and NetworkPolicy is not read here.
	for _, k := range sortedWorkloadKeys(c.workloads) {
		w := c.workloads[k]
		for _, spec := range w.specs {
			for _, ctr := range spec.Containers {
				for _, p := range ctr.Ports {
					proto, ok := k8sProto(p.Protocol)
					if !ok {
						continue
					}
					if out[k] == nil {
						out[k] = exposureSet{}
					}
					out[k].add(p.ContainerPort, proto, "kubectl:pod-network", ZoneClusterInternal)
					if p.HostPort > 0 || spec.HostNetwork {
						out[k].add(p.ContainerPort, proto, "kubectl:node-port", zoneOr(opt.NodePortZone))
					}
				}
			}
		}
	}
	return out, nil
}

func (c *k8sCluster) asset(w *k8sWorkload, opt K8sOptions, exp exposureSet) (snapshot.Asset, error) {
	id := k8sID(opt.Cluster + ":" + w.Namespace + ":" + strings.ToLower(w.Kind) + ":" + w.Name)
	asset := snapshot.Asset{
		ID:       id,
		Name:     opt.Cluster + "/" + w.Namespace + "/" + w.Kind + "/" + w.Name,
		Kind:     "k8s_workload",
		Zones:    []string{},
		Facts:    []snapshot.Fact{},
		Exposure: []snapshot.Exposure{},
	}
	images := map[string]struct{}{}
	for _, spec := range w.specs {
		for _, list := range [][]k8sContainer{spec.InitContainers, spec.Containers} {
			for _, ctr := range list {
				images[strings.TrimSpace(ctr.Image)] = struct{}{}
			}
		}
	}
	refs := make([]string, 0, len(images))
	for r := range images {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	pkgs := map[string]snapshot.Package{}
	controller := false
	for _, r := range refs {
		img, err := parseImageRef(r)
		if err != nil {
			return asset, fmt.Errorf("import k8s: %s: %w", w.key(), err)
		}
		pkg, err := img.ociPackage()
		if err != nil {
			return asset, fmt.Errorf("import k8s: %s: image %q: %w", w.key(), r, err)
		}
		pkgs[pkg.PURL] = pkg
		repo := img.Registry + "/" + img.Path
		if _, ok := ingressNginxImages[repo]; ok {
			controller = true
			if cleanVersionRE.MatchString(img.Tag) {
				canon, err := purl.Canonical(IngressNginxPURLBase + "@" + img.Tag)
				if err != nil {
					return asset, err
				}
				pkgs[canon] = snapshot.Package{PURL: canon, Version: img.Tag}
			} else {
				c.note("%s: ingress-nginx image %q has no clean vX.Y.Z tag; controller version left unknown", w.key(), r)
			}
		} else if strings.Contains(img.Path, "ingress-nginx") {
			c.note("%s: image %q is not a recognized upstream ingress-nginx controller image; no app version recorded", w.key(), r)
		}
	}
	purls := make([]string, 0, len(pkgs))
	for p := range pkgs {
		purls = append(purls, p)
	}
	sort.Strings(purls)
	asset.Inventory = snapshot.Inventory{
		Complete:   false,
		ObservedAt: opt.ObservedAt,
		Basis:      "observed",
		Confidence: "high",
		EvidenceID: k8sEvidenceID("inv", id),
		Packages:   make([]snapshot.Package, 0, len(purls)),
	}
	for _, p := range purls {
		asset.Inventory.Packages = append(asset.Inventory.Packages, pkgs[p])
	}
	if controller {
		if v, ok := c.admissionWebhook(w); ok {
			asset.Facts = append(asset.Facts, snapshot.Fact{
				Key: IngressNginxAdmissionFact, Value: v, Basis: "observed", Confidence: "high",
				ObservedAt: opt.ObservedAt, EvidenceID: k8sEvidenceID("adm", id), Source: k8sSource,
			})
		}
	}
	keys := make([]exposureKey, 0, len(exp))
	for k := range exp {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		if keys[i].proto != keys[j].proto {
			return keys[i].proto < keys[j].proto
		}
		return keys[i].source < keys[j].source
	})
	for _, k := range keys {
		zones := make([]string, 0, len(exp[k]))
		for z := range exp[k] {
			zones = append(zones, z)
		}
		sort.Strings(zones)
		asset.Exposure = append(asset.Exposure, snapshot.Exposure{
			Port: k.port, Proto: k.proto, ReachableFrom: zones,
			Basis: "observed", Confidence: "high", ObservedAt: opt.ObservedAt,
			EvidenceID: k8sEvidenceID("exp", id+"|"+k.source), Source: k.source,
		})
	}
	return asset, nil
}

// admissionWebhook decides ingress_nginx.admission_webhook for a controller.
// true: a ValidatingWebhookConfiguration points at a Service selecting this
// workload, or any controller argv element mentions validating-webhook (the
// listener is the CVE-2025-1974 attack surface even without the webhook
// object). false: every controller container has an explicit argv without
// that flag, webhook objects are in the input, every one resolves to a
// Service in the input, and none selects this workload. A shell wrapper or
// an image entrypoint (empty command and args) hides the real argv, so it
// leaves the fact unknown. Anything else is unknown and the fact is omitted.
func (c *k8sCluster) admissionWebhook(w *k8sWorkload) (string, bool) {
	flag, opaque := false, false
	for _, ctr := range controllerContainers(w) {
		switch {
		case mentionsValidatingWebhook(ctr):
			flag = true
		case argvOpaque(ctr):
			opaque = true
		}
	}
	match, unresolved := false, false
	for _, o := range c.webhooks {
		for _, wh := range o.Webhooks {
			ref := wh.ClientConfig.Service
			if ref == nil {
				unresolved = true
				continue
			}
			s := c.services[ref.Namespace+"/"+ref.Name]
			if s == nil {
				unresolved = true
				continue
			}
			if c.selects(s, w) {
				match = true
			}
		}
	}
	switch {
	case match || flag:
		return "true", true
	case opaque:
		c.note("%s: controller argv is a shell wrapper or the image entrypoint; %s omitted (unknown)", w.key(), IngressNginxAdmissionFact)
		return "", false
	case !c.sawWebhooks:
		c.note("%s: no ValidatingWebhookConfiguration in input; %s omitted (unknown)", w.key(), IngressNginxAdmissionFact)
		return "", false
	case unresolved:
		c.note("%s: a webhook targets a URL or a Service not in the input; %s omitted (unknown)", w.key(), IngressNginxAdmissionFact)
		return "", false
	}
	return "false", true
}

// controllerContainers are the containers running an ingress-nginx image.
// If none can be identified, every container counts.
func controllerContainers(w *k8sWorkload) []k8sContainer {
	var all, ctrl []k8sContainer
	for _, spec := range w.specs {
		for _, ctr := range spec.Containers {
			all = append(all, ctr)
			if strings.Contains(strings.ToLower(ctr.Image), "ingress-nginx") {
				ctrl = append(ctrl, ctr)
			}
		}
	}
	if len(ctrl) == 0 {
		return all
	}
	return ctrl
}

// mentionsValidatingWebhook is deliberately loose: any argv element that
// contains the flag name counts, including inside a shell -c string.
func mentionsValidatingWebhook(ctr k8sContainer) bool {
	for _, a := range append(append([]string{}, ctr.Command...), ctr.Args...) {
		if strings.Contains(a, "validating-webhook") {
			return true
		}
	}
	return false
}

var shells = map[string]struct{}{"sh": {}, "bash": {}, "ash": {}, "dash": {}, "zsh": {}, "ksh": {}, "busybox": {}, "dumb-init": {}, "tini": {}}

// argvOpaque reports whether the process arguments cannot be read from the
// spec: no command and no args (the image entrypoint decides), or a shell or
// init wrapper that runs a string or another program.
func argvOpaque(ctr k8sContainer) bool {
	argv := append(append([]string{}, ctr.Command...), ctr.Args...)
	if len(argv) == 0 {
		return true
	}
	for _, a := range argv {
		if a == "-c" {
			return true
		}
	}
	first := argv[0]
	if i := strings.LastIndex(first, "/"); i >= 0 {
		first = first[i+1:]
	}
	_, ok := shells[first]
	return ok
}

type imageRef struct {
	Registry string
	Path     string
	Tag      string
	Digest   string
}

// parseImageRef splits a container image reference with Docker's defaults:
// no registry means docker.io, a single path segment is under library/.
func parseImageRef(ref string) (imageRef, error) {
	var img imageRef
	rest := ref
	if i := strings.Index(rest, "@"); i >= 0 {
		img.Digest = rest[i+1:]
		rest = rest[:i]
		if !digestRE.MatchString(img.Digest) {
			return img, fmt.Errorf("image %q has an unsupported digest", ref)
		}
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "/") {
		img.Tag = rest[i+1:]
		rest = rest[:i]
		if img.Tag == "" {
			return img, fmt.Errorf("image %q has an empty tag", ref)
		}
	}
	if rest == "" || strings.ContainsAny(rest, " \t?#") {
		return img, fmt.Errorf("image %q is malformed", ref)
	}
	parts := strings.Split(rest, "/")
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		img.Registry = parts[0]
		parts = parts[1:]
	} else {
		img.Registry = "docker.io"
		if len(parts) == 1 {
			parts = append([]string{"library"}, parts...)
		}
	}
	for _, p := range parts {
		if p == "" {
			return img, fmt.Errorf("image %q is malformed", ref)
		}
	}
	img.Path = strings.ToLower(strings.Join(parts, "/"))
	img.Registry = strings.ToLower(img.Registry)
	if img.Tag == "" && img.Digest == "" {
		img.Tag = "latest"
	}
	return img, nil
}

// ociPackage writes pkg:oci/<name>@<digest-or-tag>?repository_url=...
// The version is the digest when there is one. It says nothing about the
// software inside the image.
func (img imageRef) ociPackage() (snapshot.Package, error) {
	segs := strings.Split(img.Path, "/")
	name := segs[len(segs)-1]
	version := img.Digest
	quals := "repository_url=" + purlEscape(img.Registry+"/"+img.Path)
	if version == "" {
		version = img.Tag
	} else if img.Tag != "" {
		quals += "&tag=" + purlEscape(img.Tag)
	}
	canon, err := purl.Canonical("pkg:oci/" + purlEscape(name) + "@" + purlEscape(version) + "?" + quals)
	if err != nil {
		return snapshot.Package{}, err
	}
	return snapshot.Package{PURL: canon, Version: version}, nil
}

func purlEscape(s string) string {
	r := strings.NewReplacer("%", "%25", "@", "%40", "?", "%3F", "#", "%23", "/", "%2F", "&", "%26", "=", "%3D")
	return r.Replace(s)
}

func k8sID(s string) string {
	if len(s) <= 128 {
		return s
	}
	sum := sha256.Sum256([]byte(s))
	return s[:100] + "-" + hex.EncodeToString(sum[:])[:16]
}

func k8sEvidenceID(prefix, s string) string {
	sum := sha256.Sum256([]byte(s))
	return "e-k8s-" + prefix + "-" + hex.EncodeToString(sum[:])[:16]
}
