// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package apiserver_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gardener/gardener-extension-auditing/pkg/constants"
	"github.com/gardener/gardener-extension-auditing/pkg/webhook/apiserver"
)

var _ = Describe("GardenAPIServerMutator", func() {
	const (
		namespace = "garden"

		auditWebhookConfigFileArg       = "--audit-webhook-config-file=/var/run/secrets/audit-webhook/kubeconfig"
		auditWebhookBatchMaxSizeArg     = "--audit-webhook-batch-max-size=10"
		auditWebhookBatchThrottleArg    = "--audit-webhook-batch-throttle-qps=300"
		auditWebhookTruncateEnabledArg  = "--audit-webhook-truncate-enabled=true"
		auditWebhookTruncateMaxEventArg = "--audit-webhook-truncate-max-event-size=1000000"
		auditWebhookTruncateMaxBatchArg = "--audit-webhook-truncate-max-batch-size=10000000"
	)

	var (
		fakeClient client.Client
		logger     logr.Logger
		ctx        context.Context

		auditWebhookConfigVolume      corev1.Volume
		auditWebhookConfigVolumeMount corev1.VolumeMount

		checkDeploymentIsCorrectlyMutated = func(deployment *appsv1.Deployment) {
			var container *corev1.Container
			for i := range deployment.Spec.Template.Spec.Containers {
				if deployment.Spec.Template.Spec.Containers[i].Name == "kube-apiserver" ||
					deployment.Spec.Template.Spec.Containers[i].Name == "gardener-apiserver" {
					container = &deployment.Spec.Template.Spec.Containers[i]
					break
				}
			}

			Expect(container.Args).To(ContainElements(
				auditWebhookConfigFileArg,
				auditWebhookBatchMaxSizeArg,
				auditWebhookBatchThrottleArg,
				auditWebhookTruncateEnabledArg,
				auditWebhookTruncateMaxEventArg,
				auditWebhookTruncateMaxBatchArg,
			))
			Expect(container.VolumeMounts).To(ContainElement(auditWebhookConfigVolumeMount))
			Expect(deployment.Spec.Template.Spec.Volumes).To(ContainElement(auditWebhookConfigVolume))
		}

		checkDeploymentIsNotMutated = func(deployment *appsv1.Deployment) {
			for _, c := range deployment.Spec.Template.Spec.Containers {
				if c.Name == "kube-apiserver" || c.Name == "gardener-apiserver" {
					Expect(c.Args).ToNot(ContainElement(ContainSubstring("--audit-webhook-")))

					for _, v := range c.VolumeMounts {
						Expect(v.Name).NotTo(Equal("audit-webhook-kubeconfig"))
					}
				}
			}

			for _, v := range deployment.Spec.Template.Spec.Volumes {
				Expect(v.Name).NotTo(Equal("audit-webhook-kubeconfig"))
				if v.Secret != nil {
					Expect(v.VolumeSource.Secret.SecretName).NotTo(Equal(constants.AuditWebhookKubeConfigSecretName))
				}
			}
		}
	)

	BeforeEach(func() {
		ctx = context.Background()
		logger = log.Log.WithName("test")

		auditWebhookConfigVolumeMount = corev1.VolumeMount{
			Name:      "audit-webhook-kubeconfig",
			ReadOnly:  true,
			MountPath: constants.AuditWebhookConfigDir,
		}

		auditWebhookConfigVolume = corev1.Volume{
			Name: "audit-webhook-kubeconfig",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: constants.AuditWebhookKubeConfigSecretName,
				},
			},
		}

		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()
	})

	Describe("#Mutate", func() {
		var (
			deployment *appsv1.Deployment
			mutator    *apiserver.GardenAPIServerMutator
		)

		BeforeEach(func() {
			deployment = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      "virtual-garden-kube-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "kube-apiserver",
								},
							},
						},
					},
				},
			}

			mutator = apiserver.NewGardenAPIServerMutator(fakeClient, logger)
		})

		It("should return error for wrong object type", func() {
			wrongObject := &corev1.Pod{}
			err := mutator.Mutate(ctx, wrongObject, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("wrong object type"))
		})

		It("should skip mutation when extension does not exist", func() {
			webhookSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constants.AuditWebhookKubeConfigSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"kubeconfig": []byte("test-kubeconfig-data"),
				},
			}
			Expect(fakeClient.Create(ctx, webhookSecret)).To(Succeed())

			Expect(mutator.Mutate(ctx, deployment, nil)).To(Succeed())
			checkDeploymentIsNotMutated(deployment)
		})

		It("should skip mutation when extension is being deleted", func() {
			extension := &extensionsv1alpha1.Extension{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "auditing-ext",
					Namespace:  namespace,
					Finalizers: []string{"stop-deletion"},
				},
				Spec: extensionsv1alpha1.ExtensionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: constants.ExtensionType,
					},
				},
			}
			Expect(fakeClient.Create(ctx, extension)).To(Succeed())
			Expect(fakeClient.Delete(ctx, extension)).To(Succeed())

			webhookSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constants.AuditWebhookKubeConfigSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"kubeconfig": []byte("test-kubeconfig-data"),
				},
			}
			Expect(fakeClient.Create(ctx, webhookSecret)).To(Succeed())

			Expect(mutator.Mutate(ctx, deployment, nil)).To(Succeed())
			checkDeploymentIsNotMutated(deployment)
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(extension), extension)).To(Succeed())
		})

		It("should add audit webhook configuration when extension and secret exist", func() {
			extension := &extensionsv1alpha1.Extension{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auditing-ext",
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.ExtensionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: constants.ExtensionType,
					},
				},
			}
			Expect(fakeClient.Create(ctx, extension)).To(Succeed())

			webhookSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constants.AuditWebhookKubeConfigSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"kubeconfig": []byte("test-kubeconfig-data"),
				},
			}
			Expect(fakeClient.Create(ctx, webhookSecret)).To(Succeed())

			Expect(mutator.Mutate(ctx, deployment, nil)).To(Succeed())
			checkDeploymentIsCorrectlyMutated(deployment)
		})

		It("should add secret hash annotation to deployment when secret exists", func() {
			extension := &extensionsv1alpha1.Extension{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auditing-ext",
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.ExtensionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: constants.ExtensionType,
					},
				},
			}
			Expect(fakeClient.Create(ctx, extension)).To(Succeed())

			kubeconfigData := []byte("test-kubeconfig-data")
			webhookSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constants.AuditWebhookKubeConfigSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"kubeconfig": kubeconfigData,
				},
			}
			Expect(fakeClient.Create(ctx, webhookSecret)).To(Succeed())

			Expect(mutator.Mutate(ctx, deployment, nil)).To(Succeed())

			sha := sha256.Sum256(kubeconfigData)
			short := hex.EncodeToString(sha[:])[:8]
			annotationKey := "auditing.extensions.gardener.cloud/secret-auditlog-forwarder-webhook-kubeconfig"

			Expect(deployment.Annotations).To(HaveKey(annotationKey))
			Expect(deployment.Annotations[annotationKey]).To(Equal(short))
			Expect(deployment.Spec.Template.Annotations).To(HaveKey(annotationKey))
			Expect(deployment.Spec.Template.Annotations[annotationKey]).To(Equal(short))
		})

		It("should handle empty kubeconfig data in secret", func() {
			extension := &extensionsv1alpha1.Extension{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auditing-ext",
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.ExtensionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: constants.ExtensionType,
					},
				},
			}
			Expect(fakeClient.Create(ctx, extension)).To(Succeed())

			webhookSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constants.AuditWebhookKubeConfigSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"kubeconfig": []byte(""),
				},
			}
			Expect(fakeClient.Create(ctx, webhookSecret)).To(Succeed())

			Expect(mutator.Mutate(ctx, deployment, nil)).To(Succeed())

			checkDeploymentIsCorrectlyMutated(deployment)

			Expect(deployment.Annotations).To(BeEmpty())
			Expect(deployment.Spec.Template.Annotations).To(BeEmpty())
		})

		It("should mutate both kube-apiserver and gardener-apiserver containers", func() {
			extension := &extensionsv1alpha1.Extension{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auditing-ext",
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.ExtensionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: constants.ExtensionType,
					},
				},
			}
			Expect(fakeClient.Create(ctx, extension)).To(Succeed())

			webhookSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constants.AuditWebhookKubeConfigSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"kubeconfig": []byte("test-kubeconfig-data"),
				},
			}
			Expect(fakeClient.Create(ctx, webhookSecret)).To(Succeed())

			deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, corev1.Container{
				Name: "gardener-apiserver",
			})

			Expect(mutator.Mutate(ctx, deployment, nil)).To(Succeed())
			checkDeploymentIsCorrectlyMutated(deployment)
		})

		It("should modify existing audit webhook elements", func() {
			extension := &extensionsv1alpha1.Extension{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auditing-ext",
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.ExtensionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: constants.ExtensionType,
					},
				},
			}
			Expect(fakeClient.Create(ctx, extension)).To(Succeed())

			webhookSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constants.AuditWebhookKubeConfigSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"kubeconfig": []byte("test-kubeconfig-data"),
				},
			}
			Expect(fakeClient.Create(ctx, webhookSecret)).To(Succeed())

			// Add some existing audit webhook args with different values
			deployment.Spec.Template.Spec.Containers[0].Args = []string{
				"--audit-webhook-config-file=/old/path",
				"--audit-webhook-batch-max-size=999",
			}

			Expect(mutator.Mutate(ctx, deployment, nil)).To(Succeed())
			checkDeploymentIsCorrectlyMutated(deployment)
		})

		It("should remove audit flags from command field", func() {
			extension := &extensionsv1alpha1.Extension{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auditing-ext",
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.ExtensionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: constants.ExtensionType,
					},
				},
			}
			Expect(fakeClient.Create(ctx, extension)).To(Succeed())

			webhookSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constants.AuditWebhookKubeConfigSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"kubeconfig": []byte("test-kubeconfig-data"),
				},
			}
			Expect(fakeClient.Create(ctx, webhookSecret)).To(Succeed())

			deployment.Spec.Template.Spec.Containers[0].Command = []string{
				"--audit-webhook-config-file=/old/path",
				"--audit-log-path=/var/log/audit.log",
				"--some-other-flag=value",
			}

			Expect(mutator.Mutate(ctx, deployment, nil)).To(Succeed())

			c := deployment.Spec.Template.Spec.Containers[0]
			// Audit flags (except audit-policy-file) should be removed from command
			for _, cmd := range c.Command {
				if strings.HasPrefix(cmd, "--audit-") {
					Expect(strings.HasPrefix(cmd, "--audit-policy-file=")).To(BeTrue())
				}
			}
		})

		It("should preserve audit-policy-file flag when mutating", func() {
			extension := &extensionsv1alpha1.Extension{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auditing-ext",
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.ExtensionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: constants.ExtensionType,
					},
				},
			}
			Expect(fakeClient.Create(ctx, extension)).To(Succeed())

			webhookSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constants.AuditWebhookKubeConfigSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"kubeconfig": []byte("test-kubeconfig-data"),
				},
			}
			Expect(fakeClient.Create(ctx, webhookSecret)).To(Succeed())

			deployment.Spec.Template.Spec.Containers[0].Args = []string{
				"--audit-policy-file=/etc/kubernetes/audit/policy.yaml",
				"--audit-log-path=/var/log/audit.log",
			}

			Expect(mutator.Mutate(ctx, deployment, nil)).To(Succeed())

			c := deployment.Spec.Template.Spec.Containers[0]
			Expect(c.Args).To(ContainElement("--audit-policy-file=/etc/kubernetes/audit/policy.yaml"))

			// Verify audit-log-path was removed
			hasAuditLogPath := false
			for _, arg := range c.Args {
				if strings.HasPrefix(arg, "--audit-log-path=") {
					hasAuditLogPath = true
					break
				}
			}
			Expect(hasAuditLogPath).To(BeFalse())
		})

		It("should return error when secret does not exist", func() {
			extension := &extensionsv1alpha1.Extension{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auditing-ext",
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.ExtensionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: constants.ExtensionType,
					},
				},
			}
			Expect(fakeClient.Create(ctx, extension)).To(Succeed())

			err := mutator.Mutate(ctx, deployment, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("auditlog-forwarder-webhook-kubeconfig"))
		})

		It("should not mutate when no API server containers are found", func() {
			extension := &extensionsv1alpha1.Extension{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auditing-ext",
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.ExtensionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: constants.ExtensionType,
					},
				},
			}
			Expect(fakeClient.Create(ctx, extension)).To(Succeed())

			webhookSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      constants.AuditWebhookKubeConfigSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"kubeconfig": []byte("test-kubeconfig-data"),
				},
			}
			Expect(fakeClient.Create(ctx, webhookSecret)).To(Succeed())

			deployment.Spec.Template.Spec.Containers = []corev1.Container{
				{
					Name: "other-container",
				},
			}

			Expect(mutator.Mutate(ctx, deployment, nil)).To(Succeed())

			for _, c := range deployment.Spec.Template.Spec.Containers {
				for _, arg := range c.Args {
					Expect(strings.HasPrefix(arg, "--audit-webhook-")).To(BeFalse())
				}
			}
		})
	})
})
