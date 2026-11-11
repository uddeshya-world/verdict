// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func k8sOpt() K8sOptions {
	return K8sOptions{
		Cluster: "lab", KBVersion: "demo-2026.11.08",
		Evaluation: "2026-11-08T12:00:00Z", ObservedAt: "2026-11-08T11:00:00Z",
	}
}

const controllerDeploy = `{
  "apiVersion": "apps/v1", "kind": "Deployment",
  "metadata": {"name": "ingress-nginx-controller", "namespace": "ingress-nginx"},
  "spec": {"template": {
    "metadata": {"labels": {"app.kubernetes.io/name": "ingress-nginx", "app.kubernetes.io/component": "controller"}},
    "spec": {"containers": [{"name": "controller", "image": "IMAGE", "args": ARGS,
      "ports": [{"name": "webhook", "containerPort": 8443, "protocol": "TCP"}]}]}
  }}
}`

const admissionService = `{
  "apiVersion": "v1", "kind": "Service",
  "metadata": {"name": "ingress-nginx-controller-admission", "namespace": "ingress-nginx"},
  "spec": {"type": "ClusterIP", "selector": {"app.kubernetes.io/name": "ingress-nginx", "app.kubernetes.io/component": "controller"},
    "ports": [{"port": 443, "targetPort": "webhook"}]}
}`

const lbService = `{
  "apiVersion": "v1", "kind": "Service",
  "metadata": {"name": "ingress-nginx-controller", "namespace": "ingress-nginx"},
  "spec": {"type": "LoadBalancer", "selector": {"app.kubernetes.io/name": "ingress-nginx"},
    "ports": [{"port": 443, "targetPort": 8443, "protocol": "TCP"}]}
}`

const vwc = `{
  "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
  "metadata": {"name": "ingress-nginx-admission"},
  "webhooks": [{"name": "validate.nginx.ingress.kubernetes.io",
    "clientConfig": {"service": {"namespace": "ingress-nginx", "name": "ingress-nginx-controller-admission", "port": 443}}}]
}`

func controller(image, args string) string {
	return strings.NewReplacer("IMAGE", image, "ARGS", args).Replace(controllerDeploy)
}

func list(items ...string) []byte {
	return []byte(`{"apiVersion": "v1", "kind": "List", "items": [` + strings.Join(items, ",") + `]}`)
}

func runK8s(t *testing.T, opt K8sOptions, files ...[]byte) *Result {
	t.Helper()
	var in []K8sInput
	for i, f := range files {
		in = append(in, K8sInput{Name: "in" + string(rune('0'+i)) + ".json", Data: f})
	}
	got, err := Kubernetes(in, opt)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func assetByName(t *testing.T, s *snapshot.Snapshot, suffix string) snapshot.Asset {
	t.Helper()
	for _, a := range s.Assets {
		if strings.HasSuffix(a.Name, suffix) {
			return a
		}
	}
	t.Fatalf("no asset %s in %+v", suffix, s.Assets)
	return snapshot.Asset{}
}

func admissionFact(a snapshot.Asset) *snapshot.Fact {
	for i := range a.Facts {
		if a.Facts[i].Key == IngressNginxAdmissionFact {
			return &a.Facts[i]
		}
	}
	return nil
}

func hasPURLPrefix(a snapshot.Asset, prefix string) bool {
	for _, p := range a.Inventory.Packages {
		if strings.HasPrefix(p.PURL, prefix) {
			return true
		}
	}
	return false
}

func TestSelectorMatching(t *testing.T) {
	labels := map[string]string{"app": "web", "tier": "front"}
	cases := []struct {
		sel  map[string]string
		want bool
	}{
		{map[string]string{"app": "web"}, true},
		{map[string]string{"app": "web", "tier": "front"}, true},
		{map[string]string{"app": "web", "tier": "back"}, false},
		{map[string]string{"app": "web", "missing": "x"}, false},
		{map[string]string{}, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := selectorMatches(c.sel, labels); got != c.want {
			t.Errorf("selector %v: got %v want %v", c.sel, got, c.want)
		}
	}
	// A Service in another namespace with a matching selector does not select.
	other := strings.Replace(admissionService, `"namespace": "ingress-nginx"`, `"namespace": "other"`, 1)
	got := runK8s(t, k8sOpt(), list(controller("registry.k8s.io/ingress-nginx/controller:v1.11.4", `[]`), other))
	a := assetByName(t, got.Snapshot, "ingress-nginx-controller")
	for _, e := range a.Exposure {
		if strings.Contains(e.Source, "service/") {
			t.Fatalf("cross-namespace service selected: %+v", e)
		}
	}
}

func TestControllerVersionAndWebhookFromFullInput(t *testing.T) {
	opt := k8sOpt()
	opt.LoadBalancerZone = "internet"
	got := runK8s(t, opt, list(controller("registry.k8s.io/ingress-nginx/controller:v1.11.4", `[]`), admissionService, lbService, vwc))
	a := assetByName(t, got.Snapshot, "ingress-nginx-controller")
	if a.Kind != "k8s_workload" || a.Inventory.Complete || a.Inventory.Basis != "observed" || a.Inventory.Confidence != "high" {
		t.Fatalf("%+v", a)
	}
	if !hasPURLPrefix(a, "pkg:generic/ingress-nginx@v1.11.4") || !hasPURLPrefix(a, "pkg:oci/controller@v1.11.4") {
		t.Fatalf("packages %+v", a.Inventory.Packages)
	}
	if f := admissionFact(a); f == nil || f.Value != "true" {
		t.Fatalf("fact %+v", f)
	}
	var zones []string
	for _, e := range a.Exposure {
		if e.Port == 8443 {
			zones = append(zones, e.ReachableFrom...)
		}
	}
	joined := strings.Join(zones, ",")
	if !strings.Contains(joined, "internet") || !strings.Contains(joined, "cluster-internal") {
		t.Fatalf("8443 zones %v", zones)
	}
}

func TestDigestOnlyImageHasNoAppVersion(t *testing.T) {
	digest := "registry.k8s.io/ingress-nginx/controller@sha256:" + strings.Repeat("b", 64)
	got := runK8s(t, k8sOpt(), list(controller(digest, `[]`), admissionService, vwc))
	a := assetByName(t, got.Snapshot, "ingress-nginx-controller")
	if hasPURLPrefix(a, "pkg:generic/ingress-nginx") {
		t.Fatalf("digest-only image must not get an app version: %+v", a.Inventory.Packages)
	}
	if !hasPURLPrefix(a, "pkg:oci/controller@sha256:") {
		t.Fatalf("%+v", a.Inventory.Packages)
	}
	// Mirrors and non-clean tags are not guessed either.
	for _, img := range []string{
		"harbor.corp.example/ingress-nginx/controller:v1.11.4",
		"registry.k8s.io/ingress-nginx/controller:v1.11.4-custom",
		"registry.k8s.io/ingress-nginx/controller:latest",
	} {
		got := runK8s(t, k8sOpt(), list(controller(img, `[]`)))
		if hasPURLPrefix(got.Snapshot.Assets[0], "pkg:generic/ingress-nginx") {
			t.Fatalf("%s produced an app version", img)
		}
	}
	// A clean tag with a digest keeps the tag as the version.
	pinned := "registry.k8s.io/ingress-nginx/controller:v1.12.1@sha256:" + strings.Repeat("c", 64)
	got = runK8s(t, k8sOpt(), list(controller(pinned, `[]`)))
	if !hasPURLPrefix(got.Snapshot.Assets[0], "pkg:generic/ingress-nginx@v1.12.1") {
		t.Fatalf("%+v", got.Snapshot.Assets[0].Inventory.Packages)
	}
}

func TestWebhookAbsentOmitsFact(t *testing.T) {
	got := runK8s(t, k8sOpt(), list(controller("registry.k8s.io/ingress-nginx/controller:v1.11.4", `[]`), admissionService))
	a := assetByName(t, got.Snapshot, "ingress-nginx-controller")
	if f := admissionFact(a); f != nil {
		t.Fatalf("fact must be omitted without webhook objects: %+v", f)
	}
	if !strings.Contains(strings.Join(got.Skipped, "\n"), "omitted") {
		t.Fatalf("notes %v", got.Skipped)
	}
	// The listener flag alone is enough for true: it is the attack surface.
	got = runK8s(t, k8sOpt(), list(controller("registry.k8s.io/ingress-nginx/controller:v1.11.4", `["--validating-webhook=:8443"]`)))
	if f := admissionFact(got.Snapshot.Assets[0]); f == nil || f.Value != "true" {
		t.Fatalf("fact %+v", f)
	}
}

// An unrelated, fully resolvable webhook (cert-manager).
const certManagerVWC = `{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
  "metadata": {"name": "cert-manager-webhook"},
  "webhooks": [{"name": "webhook.cert-manager.io",
    "clientConfig": {"service": {"namespace": "cert-manager", "name": "cert-manager-webhook", "port": 443}}}]}`

const certManagerSvc = `{"apiVersion": "v1", "kind": "Service", "metadata": {"name": "cert-manager-webhook", "namespace": "cert-manager"},
  "spec": {"selector": {"app.kubernetes.io/name": "webhook"}, "ports": [{"port": 443, "targetPort": 10250}]}}`

func TestWebhookOpaqueArgv(t *testing.T) {
	img := "registry.k8s.io/ingress-nginx/controller:v1.11.4"
	withCommand := func(cmd string) string {
		return strings.Replace(controller(img, `[]`), `"args": []`, `"command": `+cmd, 1)
	}
	cases := []struct {
		name, deploy, want string
	}{
		{"shell wrapper with flag", withCommand(`["/bin/sh", "-c", "/nginx-ingress-controller --validating-webhook=:8443 --ingress-class=nginx"]`), "true"},
		{"shell wrapper without flag", withCommand(`["/bin/sh", "-c", "/nginx-ingress-controller --ingress-class=nginx"]`), ""},
		{"shell script without -c", withCommand(`["bash", "/start.sh"]`), ""},
		{"empty command and args", controller(img, `[]`), ""},
	}
	for _, tc := range cases {
		got := runK8s(t, k8sOpt(), list(tc.deploy, certManagerVWC, certManagerSvc))
		f := admissionFact(got.Snapshot.Assets[0])
		switch {
		case tc.want == "" && f != nil:
			t.Errorf("%s: want omitted, got %+v", tc.name, f)
		case tc.want != "" && (f == nil || f.Value != tc.want):
			t.Errorf("%s: want %s, got %+v", tc.name, tc.want, f)
		}
		if tc.want == "" && !strings.Contains(strings.Join(got.Skipped, "\n"), "shell wrapper or the image entrypoint") {
			t.Errorf("%s: no note: %v", tc.name, got.Skipped)
		}
	}
}

func TestWebhookFalseOnlyWhenEverythingResolves(t *testing.T) {
	otherVWC, otherSvc := certManagerVWC, certManagerSvc
	img := "registry.k8s.io/ingress-nginx/controller:v1.11.4"
	explicit := `["/nginx-ingress-controller", "--ingress-class=nginx"]`
	got := runK8s(t, k8sOpt(), list(controller(img, explicit), otherVWC, otherSvc))
	if f := admissionFact(got.Snapshot.Assets[0]); f == nil || f.Value != "false" {
		t.Fatalf("explicit argv without the flag plus unrelated VWC: want false, got %+v", f)
	}
	// Same, but the webhook's Service is not in the input: unknown.
	got = runK8s(t, k8sOpt(), list(controller(img, explicit), otherVWC))
	if f := admissionFact(got.Snapshot.Assets[0]); f != nil {
		t.Fatalf("unresolved webhook must leave the fact unknown: %+v", f)
	}
	// The listener flag wins over a missing webhook object.
	got = runK8s(t, k8sOpt(), list(controller(img, `["--validating-webhook", ":8443"]`), otherVWC, otherSvc))
	if f := admissionFact(got.Snapshot.Assets[0]); f == nil || f.Value != "true" {
		t.Fatalf("want true: %+v", f)
	}
}

func TestUnknownZoneWithoutFlag(t *testing.T) {
	ingress := `{"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": "i", "namespace": "ingress-nginx"},
	  "spec": {"rules": [{"http": {"paths": [{"backend": {"service": {"name": "ingress-nginx-controller", "port": {"number": 443}}}}]}}]}}`
	got := runK8s(t, k8sOpt(), list(controller("registry.k8s.io/ingress-nginx/controller:v1.11.4", `[]`), lbService, ingress))
	a := got.Snapshot.Assets[0]
	sawLB, sawIng := false, false
	for _, e := range a.Exposure {
		switch {
		case strings.Contains(e.Source, "service/"):
			sawLB = true
			if !contains(e.ReachableFrom, ZoneUnknown) || contains(e.ReachableFrom, "internet") {
				t.Fatalf("LoadBalancer without flag: %+v", e)
			}
		case strings.Contains(e.Source, "ingress/"):
			sawIng = true
			if len(e.ReachableFrom) != 1 || e.ReachableFrom[0] != ZoneUnknown {
				t.Fatalf("Ingress without flag: %+v", e)
			}
		}
	}
	if !sawLB || !sawIng {
		t.Fatalf("%+v", a.Exposure)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestMultipleInputFiles(t *testing.T) {
	img := "registry.k8s.io/ingress-nginx/controller:v1.11.4"
	single := []byte(controller(img, `[]`))
	rest := list(admissionService, vwc)
	got := runK8s(t, k8sOpt(), single, rest)
	if f := admissionFact(got.Snapshot.Assets[0]); f == nil || f.Value != "true" {
		t.Fatalf("webhook in the second file was not joined: %+v", f)
	}
	// Order of files does not change output.
	again := runK8s(t, k8sOpt(), rest, single)
	a, _ := json.Marshal(got.Snapshot)
	b, _ := json.Marshal(again.Snapshot)
	if !bytes.Equal(a, b) {
		t.Fatalf("output depends on file order")
	}
	// The same object in two files is rejected.
	if _, err := Kubernetes([]K8sInput{{Name: "a", Data: single}, {Name: "b", Data: single}}, k8sOpt()); err == nil {
		t.Fatal("duplicate object accepted")
	}
}

func TestMalformedInputRejected(t *testing.T) {
	img := "registry.k8s.io/ingress-nginx/controller:v1.11.4"
	cases := map[string][]byte{
		"empty":         {},
		"not json":      []byte(`{"kind": "List", "items": [`),
		"trailing":      []byte(controller(img, `[]`) + `{}`),
		"no kind":       []byte(`{"items": []}`),
		"list no items": []byte(`{"apiVersion": "v1", "kind": "List"}`),
		"item no name":  list(`{"apiVersion": "v1", "kind": "Service", "metadata": {"namespace": "x"}, "spec": {}}`),
		"no namespace":  list(`{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "x"}, "spec": {}}`),
		"no template":   list(`{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "x", "namespace": "y"}, "spec": {}}`),
		"no image":      list(controller("", `[]`)),
		"bad digest":    list(controller("registry.k8s.io/ingress-nginx/controller@sha256:zz", `[]`)),
		"wrong type":    list(strings.Replace(controller(img, `[]`), `"containerPort": 8443`, `"containerPort": "8443"`, 1)),
		"bad port":      list(strings.Replace(lbService, `"port": 443`, `"port": 0`, 1), controller(img, `[]`)),
		"nested list":   list(`{"apiVersion": "v1", "kind": "List", "metadata": {"name": "x"}, "items": []}`),
		"no workloads":  list(admissionService),
	}
	for name, data := range cases {
		if _, err := Kubernetes([]K8sInput{{Name: name, Data: data}}, k8sOpt()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad := k8sOpt()
	bad.Cluster = "has/slash"
	if _, err := Kubernetes([]K8sInput{{Name: "x", Data: list(controller(img, `[]`))}}, bad); err == nil {
		t.Error("bad cluster name accepted")
	}
}

func TestNetworkPolicyDoesNotNarrow(t *testing.T) {
	img := "registry.k8s.io/ingress-nginx/controller:v1.11.4"
	np := `{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "deny", "namespace": "ingress-nginx"},
	  "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}}`
	without := runK8s(t, k8sOpt(), list(controller(img, `[]`), admissionService))
	with := runK8s(t, k8sOpt(), list(controller(img, `[]`), admissionService, np))
	a, _ := json.Marshal(without.Snapshot)
	b, _ := json.Marshal(with.Snapshot)
	if !bytes.Equal(a, b) {
		t.Fatal("NetworkPolicy changed the snapshot")
	}
	if !strings.Contains(strings.Join(with.Skipped, "\n"), "NetworkPolicy is not used to narrow exposure") {
		t.Fatalf("%v", with.Skipped)
	}
}

func TestPodFoldsIntoOwningDeployment(t *testing.T) {
	pod := `{"apiVersion": "v1", "kind": "Pod",
	  "metadata": {"name": "ingress-nginx-controller-abc12-xyz", "namespace": "ingress-nginx",
	    "labels": {"pod-template-hash": "abc12"},
	    "ownerReferences": [{"kind": "ReplicaSet", "name": "ingress-nginx-controller-abc12", "controller": true}]},
	  "spec": {"containers": [{"name": "c", "image": "registry.k8s.io/ingress-nginx/controller:v1.11.3"}]}}`
	got := runK8s(t, k8sOpt(), list(controller("registry.k8s.io/ingress-nginx/controller:v1.11.4", `[]`), pod))
	if len(got.Snapshot.Assets) != 1 {
		t.Fatalf("pod was not folded: %+v", got.Snapshot.Assets)
	}
	a := got.Snapshot.Assets[0]
	if !hasPURLPrefix(a, "pkg:generic/ingress-nginx@v1.11.3") || !hasPURLPrefix(a, "pkg:generic/ingress-nginx@v1.11.4") {
		t.Fatalf("both scheduled versions must be listed: %+v", a.Inventory.Packages)
	}
}

func TestParseImageRef(t *testing.T) {
	cases := map[string]imageRef{
		"nginx":                      {Registry: "docker.io", Path: "library/nginx", Tag: "latest"},
		"nginx:1.27":                 {Registry: "docker.io", Path: "library/nginx", Tag: "1.27"},
		"localhost:5000/app:v1":      {Registry: "localhost:5000", Path: "app", Tag: "v1"},
		"ghcr.io/org/app":            {Registry: "ghcr.io", Path: "org/app", Tag: "latest"},
		"registry.k8s.io/a/b:v1.2.3": {Registry: "registry.k8s.io", Path: "a/b", Tag: "v1.2.3"},
	}
	for in, want := range cases {
		got, err := parseImageRef(in)
		if err != nil || got != want {
			t.Errorf("%s: got %+v err %v", in, got, err)
		}
	}
}
