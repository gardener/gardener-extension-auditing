// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package auditlogforwarder

import (
	"context"
	"fmt"
	"time"

	forwarderconfigv1alpha1 "github.com/gardener/auditlog-forwarder/pkg/apis/config/v1alpha1"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/component"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	"github.com/gardener/gardener/pkg/utils"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/kubernetes/health"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/retry"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-auditing/pkg/constants"
	"github.com/gardener/gardener-extension-auditing/pkg/secrets"
)

const (
	managedResourceName = "extension-auditing"
)

// ShootMetadata contains identifying information about a Gardener shoot cluster.
// This metadata is used to enrich audit logs with context about which shoot
// cluster generated the audit events.
type ShootMetadata struct {
	// ID is the unique identifier of the shoot cluster.
	ID string
	// Name is the name of the shoot cluster.
	Name string
	// Namespace is namespace of the shoot cluster.
	Namespace string
}

// SeedMetadata contains identifying information about a Gardener seed cluster.
// This metadata provides context about which seed cluster is hosting the shoot
// that generated the audit events.
type SeedMetadata struct {
	// ID is the unique identifier of the seed cluster.
	ID string
	// Name is the name of the seed cluster.
	Name string
}

// GardenerMetadata aggregates metadata about both the shoot and seed clusters.
// This combined metadata is injected into audit logs to provide full context
// about the Gardener environment where the audit events originated.
type GardenerMetadata struct {
	// ShootMetadata contains information about the shoot cluster.
	ShootMetadata ShootMetadata
	// SeedMetadata contains information about the seed cluster hosting the shoot.
	SeedMetadata SeedMetadata
}

// Values is a set of configuration values for the auditing service.
type Values struct {
	// Image is the container image to use for the auditlog-forwarder.
	Image string

	// Metadata is additional info that is going to be used to enrich the collected logs.
	Metadata GardenerMetadata

	// AuditOutputs is a list of audit backends that will be used by auditlog-forwarder to send events to.
	AuditOutputs []Output
}

// Output defines a destination where audit events will be forwarded.
// This structure allows for extensibility to support additional output types in the future.
type Output struct {
	// HTTP specifies the configuration for an HTTP-based audit output.
	// When configured, audit events will be forwarded to the specified HTTP endpoint.
	HTTP *OutputHTTP
}

// OutputHTTP defines the configuration for forwarding audit events to an HTTP endpoint.
// This output type sends audit events over HTTPS to a remote server with proper TLS authentication.
type OutputHTTP struct {
	// URL is the HTTP endpoint where audit events will be sent.
	// This should be a complete HTTPS URL including the protocol, host, and path.
	URL string
	// TLSSecretName is the name of the Kubernetes Secret containing TLS certificates
	// for client authentication when connecting to the HTTP endpoint.
	// The secret should contain client.crt, client.key, and ca.crt files.
	TLSSecretName string
}

// New creates a new instance of component.DeployWaiter for auditing services.
func New(
	client client.Client,
	reader client.Reader,
	namespace string,
	secretsManager secretsmanager.Interface,
	values Values,
) component.DeployWaiter {
	return &auditlogForwarder{
		client:         client,
		reader:         reader,
		namespace:      namespace,
		secretsManager: secretsManager,
		values:         values,
	}
}

type auditlogForwarder struct {
	client         client.Client
	reader         client.Reader
	namespace      string
	secretsManager secretsmanager.Interface
	values         Values
}

func (r *auditlogForwarder) Deploy(ctx context.Context) error {
	configs := secrets.ConfigsFor(r.namespace)
	generatedSecrets, err := extensionssecretsmanager.GenerateAllSecrets(ctx, r.secretsManager, configs)
	if err != nil {
		return err
	}

	caBundle, found := r.secretsManager.Get(secrets.CAName)
	if !found {
		return fmt.Errorf("secret %q not found", secrets.CAName)
	}

	data, err := r.computeResourcesData(generatedSecrets, caBundle)
	if err != nil {
		return err
	}

	if err := managedresources.CreateForSeed(ctx, r.client, r.namespace, managedResourceName, false, data); err != nil {
		return fmt.Errorf("failed to create ManagedResource for Seed: %w", err)
	}

	return nil
}

func (r *auditlogForwarder) Destroy(ctx context.Context) error {
	return managedresources.Delete(ctx, r.client, r.namespace, managedResourceName, false)
}

// TimeoutWaitForManagedResource is the timeout used while waiting for the ManagedResources
// to become healthy or deleted.
var TimeoutWaitForManagedResource = 2 * time.Minute

func (r *auditlogForwarder) Wait(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	if err := managedresources.WaitUntilHealthy(timeoutCtx, r.client, r.namespace, managedResourceName); err != nil {
		return err
	}

	timeoutRoulloutCtx, cancelWaitRollout := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelWaitRollout()

	return retry.Until(timeoutRoulloutCtx, 5*time.Second, health.IsDeploymentUpdated(r.reader, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.AuditlogForwarder,
			Namespace: r.namespace,
		},
	}))
}

func (r *auditlogForwarder) WaitCleanup(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilDeleted(timeoutCtx, r.client, r.namespace, managedResourceName)
}

func (r *auditlogForwarder) computeResourcesData(generatedSecrets map[string]*corev1.Secret, caBundle *corev1.Secret) (map[string][]byte, error) {
	forwarderConfiguration := forwarderconfigv1alpha1.AuditlogForwarder{
		Server: forwarderconfigv1alpha1.Server{
			Port: 10443,
			TLS: forwarderconfigv1alpha1.TLS{
				CertFile: "/etc/auditlog-forwarder/tls/tls.crt",
				KeyFile:  "/etc/auditlog-forwarder/tls/tls.key",
				// mTLS: validate kube-apiserver client certs signed by our CA
				ClientCAFile: "/etc/auditlog-forwarder/ca/ca.crt",
			},
		},
		InjectAnnotations: map[string]string{
			"shoot.gardener.cloud/name":      r.values.Metadata.ShootMetadata.Name,
			"shoot.gardener.cloud/namespace": r.values.Metadata.ShootMetadata.Namespace,
			"shoot.gardener.cloud/id":        r.values.Metadata.ShootMetadata.ID,
			"seed.gardener.cloud/name":       r.values.Metadata.SeedMetadata.Name,
			"seed.gardener.cloud/id":         r.values.Metadata.SeedMetadata.ID,
		},
	}

	for _, output := range r.values.AuditOutputs {
		if http := output.HTTP; http != nil {
			httpOut := forwarderconfigv1alpha1.OutputHTTP{
				URL: http.URL,
				TLS: &forwarderconfigv1alpha1.ClientTLS{
					CAFile:   "/etc/auditlog-forwarder/outputs/http/" + http.TLSSecretName + "/" + "ca.crt",
					CertFile: "/etc/auditlog-forwarder/outputs/http/" + http.TLSSecretName + "/" + "client.crt",
					KeyFile:  "/etc/auditlog-forwarder/outputs/http/" + http.TLSSecretName + "/" + "client.key",
				},
			}
			forwarderConfiguration.Outputs = append(forwarderConfiguration.Outputs, forwarderconfigv1alpha1.Output{
				HTTP: &httpOut,
			})
		}
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(forwarderconfigv1alpha1.AddToScheme(scheme))
	yamlSerializer := json.NewSerializerWithOptions(json.DefaultMetaFactory, scheme, scheme, json.SerializerOptions{Yaml: true})

	data, err := runtime.Encode(yamlSerializer, &forwarderConfiguration)
	if err != nil {
		return nil, err
	}

	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.AuditlogForwarder + "-config",
			Namespace: r.namespace,
			Labels:    getLabels(),
		},
		Data: map[string]string{
			"config.yaml": string(data),
		},
	}

	utilruntime.Must(kubernetesutils.MakeUnique(config))

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.AuditlogForwarder,
			Namespace: r.namespace,
			Labels:    utils.MergeStringMaps(getLabels(), getHALabels()),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             ptr.To[int32](1),
			RevisionHistoryLimit: ptr.To[int32](2),
			Selector: &metav1.LabelSelector{
				MatchLabels: getLabels(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: utils.MergeStringMaps(getLabels(), map[string]string{
						v1beta1constants.LabelNetworkPolicyToDNS:            v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPublicNetworks: v1beta1constants.LabelNetworkPolicyAllowed,
					}),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:           constants.AuditlogForwarder,
					AutomountServiceAccountToken: ptr.To(false),
					PriorityClassName:            v1beta1constants.PriorityClassNameShootControlPlane500,
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
								Weight: 100,
								PodAffinityTerm: corev1.PodAffinityTerm{
									TopologyKey:   corev1.LabelHostname,
									LabelSelector: &metav1.LabelSelector{MatchLabels: getLabels()},
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
							Name:  constants.AuditlogForwarder,
							Image: r.values.Image,
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
							VolumeMounts: func() []corev1.VolumeMount {
								volumeMounts := []corev1.VolumeMount{
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
								}

								// Add volume mounts for each HTTP output TLS secret
								for _, output := range r.values.AuditOutputs {
									if http := output.HTTP; http != nil && http.TLSSecretName != "" {
										volumeMounts = append(volumeMounts, corev1.VolumeMount{
											Name:      "http-output-" + http.TLSSecretName,
											ReadOnly:  true,
											MountPath: "/etc/auditlog-forwarder/outputs/http/" + http.TLSSecretName,
										})
									}
								}

								return volumeMounts
							}(),
						},
					},
					Volumes: func() []corev1.Volume {
						volumes := []corev1.Volume{
							{
								Name: "config",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: config.Name,
										},
									},
								},
							},
							{
								Name: "tls",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName: generatedSecrets[constants.AuditlogForwarderTLSSecretName].Name,
										Items: []corev1.KeyToPath{
											{
												Key:  secretsutils.DataKeyCertificate,
												Path: "tls.crt",
											},
											{
												Key:  secretsutils.DataKeyPrivateKey,
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
										SecretName: caBundle.Name,
										Items: []corev1.KeyToPath{
											{
												Key:  secretsutils.DataKeyCertificateBundle,
												Path: "ca.crt",
											},
										},
									},
								},
							},
						}

						// Add volumes for each HTTP output TLS secret
						for _, output := range r.values.AuditOutputs {
							if http := output.HTTP; http != nil && http.TLSSecretName != "" {
								volumes = append(volumes, corev1.Volume{
									Name: "http-output-" + http.TLSSecretName,
									VolumeSource: corev1.VolumeSource{
										Secret: &corev1.SecretVolumeSource{
											SecretName: http.TLSSecretName,
										},
									},
								})
							}
						}

						return volumes
					}(),
				},
			},
		},
	}

	utilruntime.Must(references.InjectAnnotations(deploy))

	var (
		webhookPort = networkingv1.NetworkPolicyPort{
			Protocol: ptr.To(corev1.ProtocolTCP),
			Port:     ptr.To(intstr.FromInt(10443)),
		}
	)
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        constants.AuditlogForwarder,
			Namespace:   r.namespace,
			Annotations: map[string]string{
				// "prometheus.io/scrape": "true",
				// "prometheus.io/port":   metricsPort.Port.String(),
				// "prometheus.io/name": constants.AuditlogForwarder,
			},
			Labels: getLabels(),
		},
		Spec: corev1.ServiceSpec{
			Selector: getLabels(),
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       10443,
					TargetPort: intstr.FromInt(10443),
				},
			},
		},
	}

	if err := gardenerutils.InjectNetworkPolicyAnnotationsForWebhookTargets(service, webhookPort); err != nil {
		return nil, err
	}

	// serviceMonitor := &monitoringv1.ServiceMonitor{
	// 	ObjectMeta: monitoringutils.ConfigObjectMeta(constants.ApplicationName, r.namespace, "shoot"),
	// 	Spec: monitoringv1.ServiceMonitorSpec{
	// 		Selector: metav1.LabelSelector{MatchLabels: getLabels()},
	// 		Endpoints: []monitoringv1.Endpoint{{
	// 			Port:                 "http-api",
	// 			Scheme:               "http",
	// 			HonorLabels:          false,
	// 			Path:                 "/api/v2/metrics/prometheus",
	// 			TLSConfig:            &monitoringv1.TLSConfig{SafeTLSConfig: monitoringv1.SafeTLSConfig{InsecureSkipVerify: ptr.To(true)}},
	// 			MetricRelabelConfigs: monitoringutils.StandardMetricRelabelConfig("auditing-auditlogforwarder_.+"),
	// 		}},
	// 	},
	// }

	kubeConfig := &clientcmdv1.Config{
		Clusters: []clientcmdv1.NamedCluster{{
			Name: constants.ApplicationName,
			Cluster: clientcmdv1.Cluster{
				Server:                fmt.Sprintf("https://%s.%s.svc:10443/audit", constants.AuditlogForwarder, r.namespace),
				CertificateAuthority:  fmt.Sprintf("%s/%s", constants.AuditWebhookCADir, secretsutils.DataKeyCertificateBundle),
				InsecureSkipTLSVerify: false,
			},
		}},
		Contexts: []clientcmdv1.NamedContext{{
			Name: constants.ApplicationName,
			Context: clientcmdv1.Context{
				Cluster:  constants.ApplicationName,
				AuthInfo: constants.ApplicationName,
			},
		}},
		CurrentContext: constants.ApplicationName,
		AuthInfos: []clientcmdv1.NamedAuthInfo{{
			Name: constants.ApplicationName,
			AuthInfo: clientcmdv1.AuthInfo{
				ClientCertificateData: generatedSecrets[constants.AuditlogForwarderClientTLSSecretName].Data[secretsutils.DataKeyCertificate],
				ClientKeyData:         generatedSecrets[constants.AuditlogForwarderClientTLSSecretName].Data[secretsutils.DataKeyPrivateKey],
			},
		}},
	}

	kubeAPIServerKubeConfig, err := runtime.Encode(clientcmdlatest.Codec, kubeConfig)
	if err != nil {
		return nil, err
	}

	kubeconfigSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.AuditWebhookKubeConfigSecretName,
			Namespace: r.namespace,
			Labels:    getLabels(),
		},
		Data: map[string][]byte{
			"kubeconfig": kubeAPIServerKubeConfig,
		},
	}

	// TODO add vpa
	var resources = []client.Object{
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.AuditlogForwarder,
				Namespace: r.namespace,
				Labels:    getLabels(),
			},
		},
		&policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.AuditlogForwarder,
				Namespace: r.namespace,
				Labels:    getLabels(),
			},
			Spec: policyv1.PodDisruptionBudgetSpec{
				Selector:       &metav1.LabelSelector{MatchLabels: getLabels()},
				MaxUnavailable: ptr.To(intstr.FromInt(1)),
			},
		},
		kubeconfigSecret,
		service,
		// serviceMonitor,
		config,
		deploy,
	}

	registry := managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)

	return registry.AddAllAndSerialize(resources...)
}

func getLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":    constants.AuditlogForwarder,
		"app.kubernetes.io/part-of": constants.ExtensionType,
	}
}

func getHALabels() map[string]string {
	return map[string]string{
		resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeServer,
	}
}
