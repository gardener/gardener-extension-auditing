// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/extensions"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gardener/gardener-extension-auditing/pkg/constants"
	"github.com/gardener/gardener-extension-auditing/pkg/webhook/kapiserver"
)

var _ = Describe("Ensurer", func() {
	const (
		namespace = "test"

		auditWebhookConfigFileArg       = "--audit-webhook-config-file=/var/run/secrets/audit-webhook/kubeconfig"
		auditWebhookBatchMaxSizeArg     = "--audit-webhook-batch-max-size=10"
		auditWebhookBatchThrottleArg    = "--audit-webhook-batch-throttle-qps=300"
		auditWebhookTruncateEnabledArg  = "--audit-webhook-truncate-enabled=true"
		auditWebhookTruncateMaxEventArg = "--audit-webhook-truncate-max-event-size=1000000"
		auditWebhookTruncateMaxBatchArg = "--audit-webhook-truncate-max-batch-size=10000000"
	)

	var (
		ctrl       *gomock.Controller
		fakeClient client.Client
		logger     logr.Logger

		ctx context.Context

		auditWebhookConfigVolume      corev1.Volume
		auditWebhookConfigVolumeMount corev1.VolumeMount

		checkDeploymentIsCorrectlyMutated = func(deployment *appsv1.Deployment) {
			// Check that the kube-apiserver container still exists and has correct configuration
			var c *corev1.Container
			for i := range deployment.Spec.Template.Spec.Containers {
				if deployment.Spec.Template.Spec.Containers[i].Name == v1beta1constants.DeploymentNameKubeAPIServer {
					c = &deployment.Spec.Template.Spec.Containers[i]
					break
				}
			}
			Expect(c).ToNot(BeNil())
			Expect(c.Args).To(ContainElements(
				auditWebhookConfigFileArg,
				auditWebhookBatchMaxSizeArg,
				auditWebhookBatchThrottleArg,
				auditWebhookTruncateEnabledArg,
				auditWebhookTruncateMaxEventArg,
				auditWebhookTruncateMaxBatchArg,
			))
			Expect(c.VolumeMounts).To(ContainElement(auditWebhookConfigVolumeMount))
			Expect(deployment.Spec.Template.Spec.Volumes).To(ContainElement(auditWebhookConfigVolume))
		}

		checkDeploymentIsNotMutated = func(deployment *appsv1.Deployment) {
			var c *corev1.Container
			for i := range deployment.Spec.Template.Spec.Containers {
				if deployment.Spec.Template.Spec.Containers[i].Name == v1beta1constants.DeploymentNameKubeAPIServer {
					c = &deployment.Spec.Template.Spec.Containers[i]
					break
				}
			}
			Expect(c).To(Not(BeNil()))

			Expect(c.Args).ToNot(ContainElement(ContainSubstring("--audit-webhook-")))

			for _, v := range c.VolumeMounts {
				Expect(v.Name).NotTo(Equal("audit-webhook-kubeconfig"))
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

		ctrl = gomock.NewController(GinkgoT())
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#EnsureKubeAPIServerDeployment", func() {
		var (
			deployment *appsv1.Deployment
			ensurer    genericmutator.Ensurer
			gctx       *mockGardenContext
		)

		BeforeEach(func() {
			deployment = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      v1beta1constants.DeploymentNameKubeAPIServer,
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: v1beta1constants.DeploymentNameKubeAPIServer,
								},
							},
						},
					},
				},
			}

			ensurer = kapiserver.NewEnsurer(fakeClient, logger)
			gctx = &mockGardenContext{}
		})

		It("should add audit webhook configuration to kube-apiserver deployment when secret exists", func() {
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

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)).To(Succeed())
			checkDeploymentIsCorrectlyMutated(deployment)
		})

		It("should add secret hash annotation to deployment when secret exists", func() {
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

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)).To(Succeed())

			sha := sha256.Sum256(kubeconfigData)
			short := hex.EncodeToString(sha[:])[:8]
			annotationKey := "auditing.extensions.gardener.cloud/secret-auditlog-forwarder-webhook-kubeconfig"

			Expect(deployment.Annotations).To(HaveKey(annotationKey))
			Expect(deployment.Annotations[annotationKey]).To(Equal(short))
			Expect(deployment.Spec.Template.Annotations).To(HaveKey(annotationKey))
			Expect(deployment.Spec.Template.Annotations[annotationKey]).To(Equal(short))
		})

		It("should modify existing audit webhook elements", func() {
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

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)).To(Succeed())
			checkDeploymentIsCorrectlyMutated(deployment)
		})

		It("should remove audit flags from command field", func() {
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

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)).To(Succeed())

			c := deployment.Spec.Template.Spec.Containers[0]
			// Audit flags (except audit-policy-file) should be removed from command
			for _, cmd := range c.Command {
				if strings.HasPrefix(cmd, "--audit-") {
					Expect(strings.HasPrefix(cmd, "--audit-policy-file=")).To(BeTrue())
				}
			}
		})

		It("should not mutate deployment when secret does not exist and shoot is not hibernated or deleted", func() {
			cluster := &extensions.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-shoot",
						Namespace: namespace,
					},
				},
			}
			gctx.cluster = cluster

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)).ToNot(Succeed())
			checkDeploymentIsNotMutated(deployment)
		})

		It("should not mutate deployment when secret does not exist and shoot is hibernated", func() {
			cluster := &extensions.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-shoot",
						Namespace: namespace,
					},
					Spec: gardencorev1beta1.ShootSpec{
						Hibernation: &gardencorev1beta1.Hibernation{
							Enabled: ptr.To(true),
						},
					},
				},
			}
			gctx.cluster = cluster

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)).To(Succeed())
			checkDeploymentIsNotMutated(deployment)
		})

		It("should not mutate deployment when secret does not exist and shoot is being deleted without extension", func() {
			now := metav1.Now()
			cluster := &extensions.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-shoot",
						Namespace:         namespace,
						DeletionTimestamp: &now,
					},
				},
			}
			gctx.cluster = cluster

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)).To(Succeed())
			checkDeploymentIsNotMutated(deployment)
		})

		It("should not mutate deployment when secret does not exist and shoot is being deleted with extension", func() {
			now := metav1.Now()
			cluster := &extensions.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-shoot",
						Namespace:         namespace,
						DeletionTimestamp: &now,
					},
				},
			}
			gctx.cluster = cluster

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

			err := ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)
			Expect(err).To(BeNotFoundError())
			Expect(err).To(MatchError(ContainSubstring("auditlog-forwarder-webhook-kubeconfig")))
		})

		It("should preserve audit-policy-file flag when mutating", func() {
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

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)).To(Succeed())

			c := deployment.Spec.Template.Spec.Containers[0]
			Expect(c.Args).To(ContainElement("--audit-policy-file=/etc/kubernetes/audit/policy.yaml"))
			Expect(slices.ContainsFunc(c.Args, func(arg string) bool {
				return strings.HasPrefix(arg, "--audit-log-path=")
			})).To(BeFalse())
		})

		It("should not mutate deployment when kube-apiserver container is not found", func() {
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

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)).To(Succeed())

			for _, c := range deployment.Spec.Template.Spec.Containers {
				for _, arg := range c.Args {
					Expect(strings.HasPrefix(arg, "--audit-webhook-")).To(BeFalse())
				}
			}
		})

		It("should handle empty kubeconfig data in secret", func() {
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

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gctx, deployment, nil)).To(Succeed())

			checkDeploymentIsCorrectlyMutated(deployment)

			Expect(deployment.Annotations).To(BeEmpty())
			Expect(deployment.Spec.Template.Annotations).To(BeEmpty())
		})
	})
})

// mockGardenContext is a mock implementation of extensionscontextwebhook.GardenContext
type mockGardenContext struct {
	cluster *extensions.Cluster
}

func (m *mockGardenContext) GetCluster(_ context.Context) (*extensions.Cluster, error) {
	if m.cluster == nil {
		return nil, fmt.Errorf("cluster not found")
	}
	return m.cluster, nil
}
