// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/importer"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func newImportK8s(stdout, stderr interface{ Write([]byte) (int, error) }) *cobra.Command {
	var inputs []string
	var out, cluster, kb, evalAt, observedAt, lbZone, npZone, ingZone string
	var maxBytes int64
	cmd := &cobra.Command{
		Use:   "k8s",
		Short: "Import kubectl JSON you already exported as one asset per workload",
		Long: `Reads local kubectl -o json output, for example:

  kubectl get pods,services,ingresses,networkpolicies,deployments,daemonsets,\
    statefulsets,validatingwebhookconfigurations -A -o json > cluster.json

Nothing is fetched from a cluster or a registry. Each Deployment, DaemonSet,
StatefulSet, or unowned Pod becomes a k8s_workload asset. Images become
pkg:oci package URLs, and the inventory is never complete because images are
opaque. Exposure comes from Services and Ingresses. ClusterIP and the pod
network are written as zone "cluster-internal", which your site policy must
classify. A Service type with no zone flag is written as "unknown", which is
treated as exposed. NetworkPolicy objects are not used to narrow exposure.`,
		RunE: func(*cobra.Command, []string) error {
			if len(inputs) == 0 || out == "" || cluster == "" || kb == "" || evalAt == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--input, --out, --cluster, --kb-version, and --evaluation-time are required")}
			}
			if _, err := time.Parse(time.RFC3339, evalAt); err != nil {
				return &ExitError{Code: 2, Err: fmt.Errorf("--evaluation-time: %w", err)}
			}
			if observedAt == "" {
				observedAt = evalAt
			}
			if _, err := time.Parse(time.RFC3339, observedAt); err != nil {
				return &ExitError{Code: 2, Err: fmt.Errorf("--observed-at: %w", err)}
			}
			if err := snapshot.ValidateCap(maxBytes); err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			files := make([]importer.K8sInput, 0, len(inputs))
			for _, path := range inputs {
				info, err := os.Stat(path)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
				if info.Size() > importer.MaxK8sInputBytes {
					return &ExitError{Code: 2, Err: fmt.Errorf("%s exceeds %d bytes", path, importer.MaxK8sInputBytes)}
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return &ExitError{Code: 2, Err: err}
				}
				files = append(files, importer.K8sInput{Name: path, Data: data})
			}
			got, err := importer.Kubernetes(files, importer.K8sOptions{
				Cluster: cluster, KBVersion: kb, Evaluation: evalAt, ObservedAt: observedAt,
				LoadBalancerZone: lbZone, NodePortZone: npZone, IngressZone: ingZone,
			})
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			for _, s := range got.Skipped {
				fmt.Fprintf(stderr, "note: %s\n", s)
			}
			body, err := canonjson.Marshal(got.Snapshot)
			if err != nil {
				return err
			}
			if err := writeSnapshot(out, body, maxBytes); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "import k8s: cluster=%s assets=%d notes=%d\n", cluster, len(got.Snapshot.Assets), len(got.Skipped))
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&inputs, "input", nil, "local kubectl JSON file; repeat for more than one")
	cmd.Flags().StringVar(&out, "out", "", "snapshot JSON to write")
	cmd.Flags().StringVar(&cluster, "cluster", "", "cluster name used in asset ids")
	cmd.Flags().StringVar(&kb, "kb-version", "", "knowledge-bundle version string")
	cmd.Flags().StringVar(&evalAt, "evaluation-time", "", "RFC3339 evaluation time; the clock is not read")
	cmd.Flags().StringVar(&observedAt, "observed-at", "", "RFC3339 time kubectl was run; defaults to --evaluation-time")
	cmd.Flags().StringVar(&lbZone, "untrusted-zone-for-loadbalancer", "", "zone LoadBalancer Services and externalIPs are reachable from, e.g. internet; unset writes unknown")
	cmd.Flags().StringVar(&npZone, "untrusted-zone-for-nodeport", "", "zone node ports, hostPort, and hostNetwork are reachable from; unset writes unknown")
	cmd.Flags().StringVar(&ingZone, "untrusted-zone-for-ingress", "", "zone Ingress backends are reachable from; unset writes unknown")
	addMaxSnapshotBytes(cmd, &maxBytes)
	return cmd
}
