// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shoot_test

import (
	"context"
	"encoding/json"
	"os"
	"slices"

	"github.com/gardener/gardener-extension-auditing/pkg/constants"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-auditing/pkg/apis/auditing/v1alpha1"
)

var (
	parentCtx context.Context
)

var _ = BeforeEach(func() {
	parentCtx = context.Background()
})

const projectNamespace = "garden-local"

func defaultShootCreationFramework() *framework.ShootCreationFramework {
	kubeconfigPath := os.Getenv("KUBECONFIG")

	return framework.NewShootCreationFramework(&framework.ShootCreationConfig{
		GardenerConfig: &framework.GardenerConfig{
			ProjectNamespace:   projectNamespace,
			GardenerKubeconfig: kubeconfigPath,
			CommonConfig:       &framework.CommonConfig{},
		},
	})
}

func defaultShoot(generateName string) *gardencorev1beta1.Shoot {
	return &gardencorev1beta1.Shoot{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName,
			Annotations: map[string]string{
				v1beta1constants.AnnotationShootCloudConfigExecutionMaxDelaySeconds: "0",
			},
		},
		Spec: gardencorev1beta1.ShootSpec{
			CloudProfile: &gardencorev1beta1.CloudProfileReference{
				Name: "local",
			},
			CredentialsBindingName: ptr.To("local"),
			Region:                 "local",
			Kubernetes: gardencorev1beta1.Kubernetes{
				Version: "1.32.0",
				Kubelet: &gardencorev1beta1.KubeletConfig{
					SerializeImagePulls: ptr.To(false),
					RegistryPullQPS:     ptr.To[int32](10),
					RegistryBurst:       ptr.To[int32](20),
				},
			},
			Networking: &gardencorev1beta1.Networking{
				Type:  ptr.To("calico"),
				Nodes: ptr.To("10.0.0.0/16"),
			},
			Provider: gardencorev1beta1.Provider{
				Type: "local",
				Workers: []gardencorev1beta1.Worker{{
					Name: "local",
					Machine: gardencorev1beta1.Machine{
						Type: "local",
					},
					CRI: &gardencorev1beta1.CRI{
						Name: gardencorev1beta1.CRINameContainerD,
					},
					Minimum: 1,
					Maximum: 1,
				}},
			},
		},
	}
}

func ensureAuditingExtensionIsEnabled(shoot *gardencorev1beta1.Shoot) error {
	config := &v1alpha1.AuditConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AuditConfiguration",
			APIVersion: "auditing.extensions.gardener.cloud/v1alpha1",
		},
		Backends: []v1alpha1.AuditBackend{
			{
				HTTP: &v1alpha1.BackendHTTP{
					URL: "https://echo-server.echo-server.svc/audit",
					TLS: v1alpha1.TLSConfig{
						SecretReferenceName: "auditlog-creds",
					},
				},
			},
		},
	}

	extensionConfig, err := json.Marshal(config)
	Expect(err).NotTo(HaveOccurred())

	shoot.Spec.Extensions = slices.DeleteFunc(shoot.Spec.Extensions, func(e gardencorev1beta1.Extension) bool {
		return e.Type == constants.ExtensionType
	})

	shoot.Spec.Extensions = append(shoot.Spec.Extensions, gardencorev1beta1.Extension{
		Type:           constants.ExtensionType,
		ProviderConfig: &runtime.RawExtension{Raw: extensionConfig},
	})
	shoot.Spec.Kubernetes.KubeAPIServer.AuditConfig = &gardencorev1beta1.AuditConfig{
		AuditPolicy: &gardencorev1beta1.AuditPolicy{
			ConfigMapRef: &corev1.ObjectReference{
				Name:      "auditlog-policy",
				Namespace: projectNamespace,
			},
		},
	}
	shoot.Spec.Resources = append(shoot.Spec.Resources, gardencorev1beta1.NamedResourceReference{
		Name: "auditlog-creds",
		ResourceRef: autoscalingv1.CrossVersionObjectReference{
			APIVersion: "v1",
			Kind:       "Secret",
			Name:       "echo-server-creds",
		},
	})
	return nil
}

func getAuditlogForwarderDeployment(ctx context.Context, c client.Client, namespace string) (*appsv1.Deployment, error) {
	forwarderDeployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.AuditlogForwarder,
			Namespace: namespace,
		},
	}

	// Verify that the auditlog-forwarder deployment exists and is deployed with the correct number of replicas
	err := c.Get(ctx, client.ObjectKeyFromObject(forwarderDeployment), forwarderDeployment)
	return forwarderDeployment, err
}

func ensureAuditlogPolicy(ctx context.Context, c client.Client) error {
	policy := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auditlog-policy",
			Namespace: projectNamespace,
		},
	}

	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, c, policy, func() error {
		policy.Data = map[string]string{
			"policy": `apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
- "RequestReceived"
rules:
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods"]
- level: Metadata
  resources:
  - group: ""
    resources: ["pods/log", "pods/status"]
`,
		}
		return nil
	})
	return err
}

func ensureNetworkPolicy(ctx context.Context, c client.Client, namespace string) error {
	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-auditlog-forwarder-to-echo-server",
			Namespace: namespace,
		},
	}

	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, c, networkPolicy, func() error {
		networkPolicy.Spec = networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":    "auditlog-forwarder",
					"app.kubernetes.io/part-of": "auditing",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app.kubernetes.io/instance": "echo-server",
									"app.kubernetes.io/name":     "echo-server",
								},
							},
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": "echo-server",
								},
							},
						},
					},
				},
			},
		}
		return nil
	})

	return err
}
