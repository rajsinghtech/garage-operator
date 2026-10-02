/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
)

// podExtrasSpecField prefixes validation paths for the v1beta1 top-level lists.
const podExtrasSpecField = "spec"

// podExtrasListenerPorts returns the TCP ports Garage binds for this cluster.
func (r *GarageCluster) podExtrasListenerPorts() map[int32]string {
	ports := map[int32]string{}
	add := func(address string, configured, def int32, what string) {
		if port, err := garageconfig.ManagedBindPort(address, configured, def, what); err == nil {
			ports[port] = what
		}
	}
	add(r.Spec.Network.RPCBindAddress, r.Spec.Network.RPCBindPort, 3901, "RPC")
	if r.Spec.S3API == nil {
		ports[3900] = "S3 API"
	} else {
		add(r.Spec.S3API.BindAddress, r.Spec.S3API.BindPort, 3900, "S3 API")
	}
	if r.Spec.Admin == nil {
		ports[3903] = "admin API"
	} else {
		add(r.Spec.Admin.BindAddress, r.Spec.Admin.BindPort, 3903, "admin API")
	}
	if r.Spec.K2VAPI != nil {
		add(r.Spec.K2VAPI.BindAddress, r.Spec.K2VAPI.BindPort, 3904, "K2V API")
	}
	switch {
	case r.Spec.WebAPI == nil:
		ports[3902] = "web"
	case r.Spec.WebAPI.Enabled == nil || *r.Spec.WebAPI.Enabled:
		add(r.Spec.WebAPI.BindAddress, r.Spec.WebAPI.BindPort, 3902, "web")
	}
	return ports
}

// validatePodExtras strictly validates the top-level initContainers,
// extraContainers and extraVolumes, and the same lists carried in the reserved
// v1beta2 transport annotations (gateway tier and node-local pools), which the
// controller consumes after conversion.
func (r *GarageCluster) validatePodExtras() error {
	ports := r.podExtrasListenerPorts()
	_, issues := v1beta2.ResolvePodExtras(v1beta2.PodExtrasInput{
		Field:           podExtrasSpecField,
		InitContainers:  r.Spec.InitContainers,
		ExtraContainers: r.Spec.ExtraContainers,
		ExtraVolumes:    r.Spec.ExtraVolumes,
		ListenerPorts:   ports,
	})
	if r.Annotations != nil {
		if raw := r.Annotations[v1beta2AnnotationNodeLocalPoolsData]; raw != "" {
			var pools []v1beta2.NodeLocalPoolSpec
			if err := json.Unmarshal([]byte(raw), &pools); err != nil {
				return fmt.Errorf("decode %s for pod extras validation: %w", v1beta2AnnotationNodeLocalPoolsData, err)
			}
			for i := range pools {
				if pools[i].PodTemplate == nil {
					continue
				}
				_, found := v1beta2.ResolvePodExtras(v1beta2.PodExtrasInput{
					Field:           fmt.Sprintf("%s[%q].podTemplate", v1beta2AnnotationNodeLocalPoolsData, pools[i].Name),
					InitContainers:  pools[i].PodTemplate.InitContainers,
					ExtraContainers: pools[i].PodTemplate.ExtraContainers,
					ExtraVolumes:    pools[i].PodTemplate.ExtraVolumes,
					ListenerPorts:   ports,
				})
				issues = append(issues, found...)
			}
		}
		if raw := r.Annotations[v1beta2AnnotationGatewayTierData]; raw != "" {
			var gateway v1beta2.GatewaySpec
			if err := json.Unmarshal([]byte(raw), &gateway); err != nil {
				return fmt.Errorf("decode %s for pod extras validation: %w", v1beta2AnnotationGatewayTierData, err)
			}
			_, found := v1beta2.ResolvePodExtras(v1beta2.PodExtrasInput{
				Field:           v1beta2AnnotationGatewayTierData,
				InitContainers:  gateway.InitContainers,
				ExtraContainers: gateway.ExtraContainers,
				ExtraVolumes:    gateway.ExtraVolumes,
				ListenerPorts:   ports,
			})
			issues = append(issues, found...)
		}
	}
	return v1beta2.PodExtrasIssuesError(issues)
}

// validatePodExtras performs the cluster-independent checks for a GarageNode:
// strict decoding, names, container shape and operator-volume mounts. Mounts of
// volumes the node inherits from its tier are checked against the cluster by
// validatePodExtrasAgainstCluster.
func (r *GarageNode) validatePodExtras() error {
	hasExtras := len(r.Spec.InitContainers) > 0 || len(r.Spec.ExtraContainers) > 0 || len(r.Spec.ExtraVolumes) > 0
	if !hasExtras {
		return nil
	}
	if r.Spec.External != nil {
		return fmt.Errorf("spec.initContainers, spec.extraContainers and spec.extraVolumes are not valid on an external GarageNode: the operator runs no pod for it")
	}
	if effectiveNodeBacking(r.Spec.Backing) == NodeBackingNodeLocalPool {
		return fmt.Errorf("spec.initContainers, spec.extraContainers and spec.extraVolumes are not valid on a node-local-pool-backed GarageNode: its pod comes from the pool's DaemonSet, so set them in spec.storage.nodeLocalPools[].podTemplate")
	}
	_, issues := v1beta2.ResolvePodExtras(v1beta2.PodExtrasInput{
		Field:                 podExtrasSpecField,
		InitContainers:        r.Spec.InitContainers,
		ExtraContainers:       r.Spec.ExtraContainers,
		ExtraVolumes:          r.Spec.ExtraVolumes,
		SkipUnknownMountCheck: r.Spec.ExtraVolumes == nil,
	})
	return v1beta2.PodExtrasIssuesError(issues)
}

// EffectivePodExtras applies the GarageNode override rule: each list that is
// non-nil on the node replaces the tier's list; the three lists are
// independent. A nil tier yields only the node's lists.
func (node *GarageNode) EffectivePodExtras(tier *v1beta2.PodTemplate) v1beta2.PodExtrasInput {
	out := v1beta2.PodExtrasInput{
		Field:           podExtrasSpecField,
		InitContainers:  node.Spec.InitContainers,
		ExtraContainers: node.Spec.ExtraContainers,
		ExtraVolumes:    node.Spec.ExtraVolumes,
	}
	if tier == nil {
		return out
	}
	if node.Spec.InitContainers == nil {
		out.InitContainers = tier.InitContainers
	}
	if node.Spec.ExtraContainers == nil {
		out.ExtraContainers = tier.ExtraContainers
	}
	if node.Spec.ExtraVolumes == nil {
		out.ExtraVolumes = tier.ExtraVolumes
	}
	return out
}

// validatePodExtrasAgainstCluster validates the merged (tier plus node
// override) lists with the parent cluster's listener ports. It is best effort:
// the node webhook sees only a snapshot of the cluster, and the controller
// repeats the check fail-closed.
func (v *GarageNodeValidator) validatePodExtrasAgainstCluster(ctx context.Context, node *GarageNode) error {
	if v == nil || v.apiReader == nil || node == nil || node.Spec.External != nil ||
		effectiveNodeBacking(node.Spec.Backing) == NodeBackingNodeLocalPool ||
		node.Spec.InitContainers == nil && node.Spec.ExtraContainers == nil && node.Spec.ExtraVolumes == nil {
		return nil
	}
	cluster := &v1beta2.GarageCluster{}
	if err := v.apiReader.Get(ctx, types.NamespacedName{Name: node.Spec.ClusterRef.Name, Namespace: node.Namespace}, cluster); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("reading GarageCluster %q to validate pod extras: %w", node.Spec.ClusterRef.Name, err)
		}
		return nil
	}
	in := node.EffectivePodExtras(cluster.PodTemplateForNode(node.Spec.Gateway))
	in.ListenerPorts = cluster.GarageListenerPorts()
	_, issues := v1beta2.ResolvePodExtras(in)
	return v1beta2.PodExtrasIssuesError(issues)
}
