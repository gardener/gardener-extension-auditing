// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package auditlogforwarder_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	forwarderconfigv1alpha1 "github.com/gardener/auditlog-forwarder/pkg/apis/config/v1alpha1"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/component"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/retry"
	retryfake "github.com/gardener/gardener/pkg/utils/retry/fake"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	fakesecretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager/fake"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"

	auditlogforwarder "github.com/gardener/gardener-extension-auditing/pkg/component/auditlog-forwarder"
)

var _ = Describe("AuditlogForwarder", func() {
	var (
		ctx context.Context

		managedResourceName = "extension-auditing"
		namespace           = "some-namespace"
		image               = "europe-docker.pkg.dev/gardener-project/releases/gardener/auditlog-forwarder:v1.0.0"

		fakeClient        client.Client
		fakeSecretManager secretsmanager.Interface
		deployer          component.DeployWaiter
		values            auditlogforwarder.Values

		fakeOps   *retryfake.Ops
		consistOf func(...client.Object) types.GomegaMatcher

		managedResource       *resourcesv1alpha1.ManagedResource
		managedResourceSecret *corev1.Secret

		deployment          *appsv1.Deployment
		service             *corev1.Service
		podDisruptionBudget *policyv1.PodDisruptionBudget
		vpa                 *vpaautoscalingv1.VerticalPodAutoscaler
		serviceAccount      *corev1.ServiceAccount
		configMap           *corev1.ConfigMap
		kubeconfigSecret    *corev1.Secret
		httpOutputSecret    *corev1.Secret

		shootMetadata auditlogforwarder.ShootMetadata
		seedMetadata  auditlogforwarder.SeedMetadata
	)

	BeforeEach(func() {
		ctx = context.Background()

		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()
		fakeSecretManager = fakesecretsmanager.New(fakeClient, namespace)

		fakeOps = &retryfake.Ops{MaxAttempts: 2}
		DeferCleanup(test.WithVars(
			&retry.Until, fakeOps.Until,
			&retry.UntilTimeout, fakeOps.UntilTimeout,
		))

		consistOf = NewManagedResourceConsistOfObjectsMatcher(fakeClient)

		managedResource = &resourcesv1alpha1.ManagedResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      managedResourceName,
				Namespace: namespace,
			},
		}
		managedResourceSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "managedresource-" + managedResource.Name,
				Namespace: namespace,
			},
		}

		shootMetadata = auditlogforwarder.ShootMetadata{
			ID:        "shoot-id-123",
			Name:      "test-shoot",
			Namespace: "garden-test",
		}
		seedMetadata = auditlogforwarder.SeedMetadata{
			ID:   "seed-id-456",
			Name: "test-seed",
		}
	})

	JustBeforeEach(func() {
		forwarderConfiguration := forwarderconfigv1alpha1.AuditlogForwarder{
			Server: forwarderconfigv1alpha1.Server{
				Port: 10443,
				TLS: forwarderconfigv1alpha1.TLS{
					CertFile:     "/etc/auditlog-forwarder/tls/tls.crt",
					KeyFile:      "/etc/auditlog-forwarder/tls/tls.key",
					ClientCAFile: "/etc/auditlog-forwarder/ca/ca.crt",
				},
			},
			InjectAnnotations: map[string]string{
				"shoot.gardener.cloud/name":      shootMetadata.Name,
				"shoot.gardener.cloud/namespace": shootMetadata.Namespace,
				"shoot.gardener.cloud/id":        shootMetadata.ID,
				"seed.gardener.cloud/name":       seedMetadata.Name,
				"seed.gardener.cloud/id":         seedMetadata.ID,
			},
			Outputs: []forwarderconfigv1alpha1.Output{
				{
					HTTP: &forwarderconfigv1alpha1.OutputHTTP{
						URL: "https://audit-backend.example.com/events",
						TLS: &forwarderconfigv1alpha1.ClientTLS{
							CAFile:   "/etc/auditlog-forwarder/outputs/http/audit-backend-tls/ca.crt",
							CertFile: "/etc/auditlog-forwarder/outputs/http/audit-backend-tls/client.crt",
							KeyFile:  "/etc/auditlog-forwarder/outputs/http/audit-backend-tls/client.key",
						},
					},
				},
			},
		}

		scheme := runtime.NewScheme()
		utilruntime.Must(forwarderconfigv1alpha1.AddToScheme(scheme))
		yamlSerializer := json.NewSerializerWithOptions(json.DefaultMetaFactory, scheme, scheme, json.SerializerOptions{Yaml: true})
		configData, err := runtime.Encode(yamlSerializer, &forwarderConfiguration)
		Expect(err).NotTo(HaveOccurred())

		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "auditlog-forwarder-config",
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":    "auditlog-forwarder",
					"app.kubernetes.io/part-of": "auditing",
				},
			},
			Data: map[string]string{
				"config.yaml": string(configData),
			},
		}
		utilruntime.Must(kubernetesutils.MakeUnique(configMap))

		deployment = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "auditlog-forwarder",
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":                                 "auditlog-forwarder",
					"app.kubernetes.io/part-of":                              "auditing",
					"high-availability-config.resources.gardener.cloud/type": "server",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas:             ptr.To[int32](1),
				RevisionHistoryLimit: ptr.To[int32](2),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app.kubernetes.io/name":    "auditlog-forwarder",
						"app.kubernetes.io/part-of": "auditing",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app.kubernetes.io/name":                        "auditlog-forwarder",
							"app.kubernetes.io/part-of":                     "auditing",
							"networking.gardener.cloud/to-dns":              "allowed",
							"networking.gardener.cloud/to-public-networks":  "allowed",
							"networking.gardener.cloud/to-private-networks": "allowed",
						},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName:           "auditlog-forwarder",
						AutomountServiceAccountToken: ptr.To(false),
						PriorityClassName:            "gardener-system-500",
						Affinity: &corev1.Affinity{
							PodAntiAffinity: &corev1.PodAntiAffinity{
								PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
									Weight: 100,
									PodAffinityTerm: corev1.PodAffinityTerm{
										TopologyKey: corev1.LabelHostname,
										LabelSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{
												"app.kubernetes.io/name":    "auditlog-forwarder",
												"app.kubernetes.io/part-of": "auditing",
											},
										},
									},
								}},
							},
						},
						SecurityContext: &corev1.PodSecurityContext{
							SeccompProfile: &corev1.SeccompProfile{
								Type: corev1.SeccompProfileTypeRuntimeDefault,
							},
						},
						Containers: []corev1.Container{
							{
								Name:  "auditlog-forwarder",
								Image: image,
								Args: []string{
									"--config=/etc/auditlog-forwarder/config/config.yaml",
								},
								Ports: []corev1.ContainerPort{
									{
										Name:          "https",
										ContainerPort: 10443,
									},
								},
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: ptr.To(false),
								},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "config",
										ReadOnly:  true,
										MountPath: "/etc/auditlog-forwarder/config",
									},
									{
										Name:      "tls",
										ReadOnly:  true,
										MountPath: "/etc/auditlog-forwarder/tls",
									},
									{
										Name:      "ca",
										ReadOnly:  true,
										MountPath: "/etc/auditlog-forwarder/ca",
									},
									{
										Name:      "http-output-audit-backend-tls",
										ReadOnly:  true,
										MountPath: "/etc/auditlog-forwarder/outputs/http/audit-backend-tls",
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "config",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: configMap.Name,
										},
									},
								},
							},
							{
								Name: "tls",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName: "auditlog-forwarder-tls",
										Items: []corev1.KeyToPath{
											{
												Key:  "tls.crt",
												Path: "tls.crt",
											},
											{
												Key:  "tls.key",
												Path: "tls.key",
											},
										},
									},
								},
							},
							{
								Name: "ca",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName: "ca-extension-auditing",
										Items: []corev1.KeyToPath{
											{
												Key:  "bundle.crt",
												Path: "ca.crt",
											},
										},
									},
								},
							},
							{
								Name: "http-output-audit-backend-tls",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName: "audit-backend-tls",
									},
								},
							},
						},
					},
				},
			},
		}
		utilruntime.Must(references.InjectAnnotations(deployment))

		service = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "auditlog-forwarder",
				Namespace: namespace,
				Annotations: map[string]string{
					"networking.resources.gardener.cloud/from-all-webhook-targets-allowed-ports": `[{"protocol":"TCP","port":10443}]`,
				},
				Labels: map[string]string{
					"app.kubernetes.io/name":    "auditlog-forwarder",
					"app.kubernetes.io/part-of": "auditing",
				},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"app.kubernetes.io/name":    "auditlog-forwarder",
					"app.kubernetes.io/part-of": "auditing",
				},
				Ports: []corev1.ServicePort{
					{
						Name:       "https",
						Port:       10443,
						TargetPort: intstr.FromInt(10443),
					},
				},
			},
		}

		podDisruptionBudget = &policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "auditlog-forwarder",
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":    "auditlog-forwarder",
					"app.kubernetes.io/part-of": "auditing",
				},
			},
			Spec: policyv1.PodDisruptionBudgetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app.kubernetes.io/name":    "auditlog-forwarder",
						"app.kubernetes.io/part-of": "auditing",
					},
				},
				MaxUnavailable: ptr.To(intstr.FromInt(1)),
			},
		}

		vpa = &vpaautoscalingv1.VerticalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "auditlog-forwarder",
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":    "auditlog-forwarder",
					"app.kubernetes.io/part-of": "auditing",
				},
			},
			Spec: vpaautoscalingv1.VerticalPodAutoscalerSpec{
				TargetRef: &autoscalingv1.CrossVersionObjectReference{
					APIVersion: appsv1.SchemeGroupVersion.String(),
					Kind:       "Deployment",
					Name:       "auditlog-forwarder",
				},
				UpdatePolicy: &vpaautoscalingv1.PodUpdatePolicy{
					UpdateMode: ptr.To(vpaautoscalingv1.UpdateModeRecreate),
				},
				ResourcePolicy: &vpaautoscalingv1.PodResourcePolicy{
					ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{{
						ContainerName:    vpaautoscalingv1.DefaultContainerResourcePolicy,
						ControlledValues: ptr.To(vpaautoscalingv1.ContainerControlledValuesRequestsOnly),
					}},
				},
			},
		}

		serviceAccount = &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "auditlog-forwarder",
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":    "auditlog-forwarder",
					"app.kubernetes.io/part-of": "auditing",
				},
			},
		}

		// Kubeconfig will be generated later after Deploy() creates the actual secrets
		kubeconfigSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "auditlog-forwarder-webhook-kubeconfig",
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":    "auditlog-forwarder",
					"app.kubernetes.io/part-of": "auditing",
				},
			},
		}

		httpOutputSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audit-backend-tls",
				Namespace: namespace,
			},
			Data: map[string][]byte{
				"ca.crt":     []byte("ca-cert-data"),
				"client.crt": []byte("client-cert-data"),
				"client.key": []byte("client-key-data"),
			},
		}

		values = auditlogforwarder.Values{
			Image: image,
			Metadata: auditlogforwarder.GardenerMetadata{
				ShootMetadata: shootMetadata,
				SeedMetadata:  seedMetadata,
			},
			AuditOutputs: []auditlogforwarder.Output{
				{
					HTTP: &auditlogforwarder.OutputHTTP{
						URL:           "https://audit-backend.example.com/events",
						TLSSecretName: "audit-backend-tls",
					},
				},
			},
		}
		deployer = auditlogforwarder.New(fakeClient, fakeClient, namespace, fakeSecretManager, values)

		Expect(fakeClient.Create(ctx, httpOutputSecret)).To(Succeed())
	})

	Describe("#Deploy", func() {
		Context("resources generation", func() {
			var expectedObjects []client.Object

			BeforeEach(func() {
				Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(BeNotFoundError())
				Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(BeNotFoundError())

				Expect(fakeClient.Create(ctx, &resourcesv1alpha1.ManagedResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:       managedResourceName,
						Namespace:  namespace,
						Generation: 1,
					},
					Status: healthyManagedResourceStatus,
				})).To(Succeed())
			})

			JustBeforeEach(func() {
				Expect(deployer.Deploy(ctx)).To(Succeed())

				Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(Succeed())
				expectedMr := &resourcesv1alpha1.ManagedResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:            managedResource.Name,
						Namespace:       managedResource.Namespace,
						ResourceVersion: "2",
						Generation:      1,
						Labels: map[string]string{
							"gardener.cloud/role": "seed-system-component",
						},
					},
					Spec: resourcesv1alpha1.ManagedResourceSpec{
						Class:       ptr.To("seed"),
						SecretRefs:  []corev1.LocalObjectReference{{Name: managedResource.Spec.SecretRefs[0].Name}},
						KeepObjects: ptr.To(false),
					},
					Status: healthyManagedResourceStatus,
				}
				utilruntime.Must(references.InjectAnnotations(expectedMr))
				Expect(managedResource).To(DeepEqual(expectedMr))

				managedResourceSecret.Name = managedResource.Spec.SecretRefs[0].Name
				Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(Succeed())

				tlsSecret, found := fakeSecretManager.Get("auditlog-forwarder-tls")
				Expect(found).To(BeTrue())

				caBundle, found := fakeSecretManager.Get("ca-extension-auditing")
				Expect(found).To(BeTrue())

				clientTLSSecret, found := fakeSecretManager.Get("auditlog-forwarder-client-tls")
				Expect(found).To(BeTrue())

				kubeConfig := &clientcmdv1.Config{
					Clusters: []clientcmdv1.NamedCluster{{
						Name: "auditing",
						Cluster: clientcmdv1.Cluster{
							Server:                   fmt.Sprintf("https://%s.%s.svc:10443/audit", "auditlog-forwarder", namespace),
							CertificateAuthorityData: caBundle.Data["bundle.crt"],
							InsecureSkipTLSVerify:    false,
						},
					}},
					Contexts: []clientcmdv1.NamedContext{{
						Name: "auditing",
						Context: clientcmdv1.Context{
							Cluster:  "auditing",
							AuthInfo: "auditing",
						},
					}},
					CurrentContext: "auditing",
					AuthInfos: []clientcmdv1.NamedAuthInfo{{
						Name: "auditing",
						AuthInfo: clientcmdv1.AuthInfo{
							ClientCertificateData: clientTLSSecret.Data["tls.crt"],
							ClientKeyData:         clientTLSSecret.Data["tls.key"],
						},
					}},
				}
				kubeAPIServerKubeConfig, err := runtime.Encode(clientcmdlatest.Codec, kubeConfig)
				Expect(err).NotTo(HaveOccurred())
				kubeconfigSecret.Data = map[string][]byte{
					"kubeconfig": kubeAPIServerKubeConfig,
				}

				deployment.Spec.Template.Spec.Volumes[1].VolumeSource.Secret.SecretName = tlsSecret.Name
				deployment.Spec.Template.Spec.Volumes[2].VolumeSource.Secret.SecretName = caBundle.Name
				utilruntime.Must(references.InjectAnnotations(deployment))

				expectedObjects = []client.Object{
					vpa,
					serviceAccount,
					podDisruptionBudget,
					kubeconfigSecret,
					service,
					configMap,
					deployment,
				}

				Expect(managedResourceSecret.Type).To(Equal(corev1.SecretTypeOpaque))
				Expect(managedResourceSecret.Immutable).To(Equal(ptr.To(true)))
				Expect(managedResourceSecret.Labels["resources.gardener.cloud/garbage-collectable-reference"]).To(Equal("true"))
			})

			It("should successfully deploy all resources", func() {
				Expect(managedResource).To(consistOf(expectedObjects...))
			})
		})
	})

	Describe("#Destroy", func() {
		It("should successfully destroy all resources", func() {
			Expect(fakeClient.Create(ctx, managedResource)).To(Succeed())
			Expect(fakeClient.Create(ctx, managedResourceSecret)).To(Succeed())

			Expect(deployer.Destroy(ctx)).To(Succeed())

			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(BeNotFoundError())
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(BeNotFoundError())
		})
	})

	Context("waiting functions", func() {
		var (
			deploymentInNamespace *appsv1.Deployment
		)

		BeforeEach(func() {
			deploymentInNamespace = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "auditlog-forwarder",
					Namespace:  namespace,
					Generation: 1,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](1),
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/name":    "auditlog-forwarder",
							"app.kubernetes.io/part-of": "auditing",
						},
					},
				},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 1,
					Replicas:           1,
					UpdatedReplicas:    1,
					AvailableReplicas:  1,
					Conditions: []appsv1.DeploymentCondition{
						{
							Type:   appsv1.DeploymentProgressing,
							Status: corev1.ConditionTrue,
							Reason: "NewReplicaSetAvailable",
						},
						{
							Type:   appsv1.DeploymentAvailable,
							Status: corev1.ConditionTrue,
						},
					},
				},
			}
		})

		Describe("#Wait", func() {
			It("should fail because reading the ManagedResource fails", func() {
				Expect(deployer.Wait(ctx)).To(MatchError(ContainSubstring("not found")))
			})

			It("should fail because the ManagedResource is unhealthy", func() {
				Expect(fakeClient.Create(ctx, &resourcesv1alpha1.ManagedResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:       managedResourceName,
						Namespace:  namespace,
						Generation: 1,
					},
					Status: unhealthyManagedResourceStatus,
				})).To(Succeed())

				Expect(deployer.Wait(ctx)).To(MatchError(ContainSubstring("is not healthy")))
			})

			It("should fail because the Deployment is not updated yet", func() {
				Expect(fakeClient.Create(ctx, &resourcesv1alpha1.ManagedResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:       managedResourceName,
						Namespace:  namespace,
						Generation: 1,
					},
					Status: healthyManagedResourceStatus,
				})).To(Succeed())

				deploymentNotUpdated := deploymentInNamespace.DeepCopy()
				deploymentNotUpdated.Status.ObservedGeneration = 0
				Expect(fakeClient.Create(ctx, deploymentNotUpdated)).To(Succeed())

				Expect(deployer.Wait(ctx)).To(MatchError(ContainSubstring("observed generation outdated (0/1)")))
			})

			It("should succeed because the ManagedResource is healthy and Deployment is updated", func() {
				Expect(fakeClient.Create(ctx, &resourcesv1alpha1.ManagedResource{
					ObjectMeta: metav1.ObjectMeta{
						Name:       managedResourceName,
						Namespace:  namespace,
						Generation: 1,
					},
					Status: healthyManagedResourceStatus,
				})).To(Succeed())

				Expect(fakeClient.Create(ctx, deploymentInNamespace)).To(Succeed())

				// Create a pod that matches the deployment's selector
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auditlog-forwarder-pod",
						Namespace: namespace,
						Labels: map[string]string{
							"app.kubernetes.io/name":    "auditlog-forwarder",
							"app.kubernetes.io/part-of": "auditing",
						},
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
						Conditions: []corev1.PodCondition{
							{
								Type:   corev1.PodReady,
								Status: corev1.ConditionTrue,
							},
						},
					},
				}
				Expect(fakeClient.Create(ctx, pod)).To(Succeed())

				Expect(deployer.Wait(ctx)).To(Succeed())
			})
		})

		Describe("#WaitCleanup", func() {
			It("should fail when the wait for the managed resource deletion times out", func() {
				Expect(fakeClient.Create(ctx, managedResource)).To(Succeed())

				Expect(deployer.WaitCleanup(ctx)).To(MatchError(ContainSubstring("still exists")))
			})

			It("should not return an error when it's already removed", func() {
				Expect(deployer.WaitCleanup(ctx)).To(Succeed())
			})
		})
	})
})

var (
	healthyManagedResourceStatus = resourcesv1alpha1.ManagedResourceStatus{
		ObservedGeneration: 1,
		Conditions: []gardencorev1beta1.Condition{
			{
				Type:   resourcesv1alpha1.ResourcesApplied,
				Status: gardencorev1beta1.ConditionTrue,
			},
			{
				Type:   resourcesv1alpha1.ResourcesHealthy,
				Status: gardencorev1beta1.ConditionTrue,
			},
		},
	}
	unhealthyManagedResourceStatus = resourcesv1alpha1.ManagedResourceStatus{
		ObservedGeneration: 1,
		Conditions: []gardencorev1beta1.Condition{
			{
				Type:   resourcesv1alpha1.ResourcesApplied,
				Status: gardencorev1beta1.ConditionFalse,
			},
			{
				Type:   resourcesv1alpha1.ResourcesHealthy,
				Status: gardencorev1beta1.ConditionFalse,
			},
		},
	}
)
