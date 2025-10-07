// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	extensionscontextwebhook "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-auditing/pkg/constants"
)

// Byte size suffixes.
const (
	B   int64 = 1
	KiB int64 = 1 << (10 * iota)
	MiB
	GiB

	KB int64 = 1000 * B
	MB int64 = 1000 * KB
	GB int64 = 1000 * MB
)

const (
	auditPolicyFilePrefix             = "--audit-policy-file="
	auditWebhookConfigFilePrefix      = "--audit-webhook-config-file="
	auditWebhookBatchMaxSizePrefix    = "--audit-webhook-batch-max-size="
	auditWebhookBatchThrottleQPS      = "--audit-webhook-batch-throttle-qps="
	auditWebhookTruncateEnabledPrefix = "--audit-webhook-truncate-enabled="
	auditWebhookTruncateMaxEventSize  = "--audit-webhook-truncate-max-event-size="
	auditWebhookTruncateMaxBatchSize  = "--audit-webhook-truncate-max-batch-size="

	auditWebhookConfigVolumeName = "audit-webhook-kubeconfig" // #nosec G101
)

type ensurer struct {
	genericmutator.NoopEnsurer
	client client.Client
	logger logr.Logger
}

// NewSecretsManager is an alias for extensionssecretsmanager.SecretsManagerForCluster.
// exposed for testing
var NewSecretsManager = extensionssecretsmanager.SecretsManagerForCluster

// EnsureKubeAPIServerDeployment ensures that the kube-apiserver deployment conforms to the auditlog-proxy requirements.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, gctx extensionscontextwebhook.GardenContext, newDeployment, _ *appsv1.Deployment) error {
	template := &newDeployment.Spec.Template
	ps := &template.Spec

	if c := extensionswebhook.ContainerWithName(ps.Containers, v1beta1constants.DeploymentNameKubeAPIServer); c != nil {
		// TODO: this secret should probably be unique or the kube-apiserver should be annotated with a hashsum
		// if it gets updated existing kube-apiserver pods would not automatically pick up the changes
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: constants.AuditWebhookKubeConfigSecretName, Namespace: newDeployment.Namespace}}
		if err := e.client.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
			// if secret is not found then probably one of the following is true
			// 1. the shoot is being hibernated in addition to auditlog extension first enablement
			// 2. the shoot is being deleted in addition to auditlog extension first enablement
			// hence we skip returning the not found error
			if !apierrors.IsNotFound(err) {
				return err
			}

			cluster, clusterErr := gctx.GetCluster(ctx)
			if clusterErr != nil {
				return clusterErr
			}

			extensionExist, extensionError := auditlogExtensionExists(ctx, e.client, newDeployment.Namespace)
			if extensionError != nil {
				return extensionError
			}

			if cluster.Shoot.DeletionTimestamp != nil && !extensionExist {
				return nil
			}

			if !controller.IsHibernationEnabled(cluster) {
				return err
			}

			return nil
		}

		data := secret.Data["kubeconfig"]
		if len(data) != 0 {
			var (
				sha           = sha256.Sum256(data)
				short         = hex.EncodeToString(sha[:])[:8]
				annotationKey = "auditing.extensions.gardener.cloud/secret-" + short
			)

			if newDeployment.Annotations == nil {
				newDeployment.Annotations = map[string]string{}
			}
			newDeployment.Annotations[annotationKey] = secret.Name
			if template.Annotations == nil {
				template.Annotations = map[string]string{}
			}
			template.Annotations[annotationKey] = secret.Name
		}

		e.ensureKubeAPIServerIsMutated(ps, c)
	}

	return nil
}

// NewEnsurer creates a new auditing mutator.
func NewEnsurer(c client.Client, logger logr.Logger) genericmutator.Ensurer {
	return &ensurer{
		logger: logger.WithName("auditing-controlplane-ensurer"),
		client: c,
	}
}

// ensureKubeAPIServerIsMutated ensures that the kube-apiserver deployment is mutated accordingly
// so that it is able to communicate with the auditlog-proxy
func (e *ensurer) ensureKubeAPIServerIsMutated(ps *corev1.PodSpec, c *corev1.Container) {
	var (
		maxEventSize = MB                // 1MB
		maxBatchSize = maxEventSize * 10 // kube-apiserver will fail to start if batchSize < eventSize, thus explicitly set higher value

		batchMaxSize     int32 = 10
		batchThrottleQPS int32 = 300
	)

	c.Command = slices.DeleteFunc(c.Command, func(x string) bool {
		return strings.HasPrefix(x, "--audit-") && !strings.HasPrefix(x, auditPolicyFilePrefix)
	})
	c.Args = slices.DeleteFunc(c.Args, func(x string) bool {
		return strings.HasPrefix(x, "--audit-") && !strings.HasPrefix(x, auditPolicyFilePrefix)
	})

	c.Args = extensionswebhook.EnsureStringWithPrefix(c.Args, auditWebhookConfigFilePrefix, constants.AuditWebhookConfigDir+"/kubeconfig")
	c.Args = extensionswebhook.EnsureStringWithPrefix(c.Args, auditWebhookBatchMaxSizePrefix, fmt.Sprintf("%v", batchMaxSize))
	c.Args = extensionswebhook.EnsureStringWithPrefix(c.Args, auditWebhookBatchThrottleQPS, fmt.Sprintf("%v", batchThrottleQPS))
	c.Args = extensionswebhook.EnsureStringWithPrefix(c.Args, auditWebhookTruncateEnabledPrefix, "true")
	c.Args = extensionswebhook.EnsureStringWithPrefix(c.Args, auditWebhookTruncateMaxEventSize, fmt.Sprintf("%v", maxEventSize))
	c.Args = extensionswebhook.EnsureStringWithPrefix(c.Args, auditWebhookTruncateMaxBatchSize, fmt.Sprintf("%v", maxBatchSize))

	c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, corev1.VolumeMount{
		Name:      auditWebhookConfigVolumeName,
		ReadOnly:  true,
		MountPath: constants.AuditWebhookConfigDir,
	})

	ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, corev1.Volume{
		Name: auditWebhookConfigVolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: constants.AuditWebhookKubeConfigSecretName,
			},
		},
	})
}

func auditlogExtensionExists(ctx context.Context, c client.Client, namespace string) (bool, error) {
	extensions := extensionsv1alpha1.ExtensionList{}
	if err := c.List(ctx, &extensions, client.InNamespace(namespace)); err != nil {
		return false, err
	}

	for _, extension := range extensions.Items {
		if extension.Spec.Type == constants.ExtensionType {
			return true, nil
		}
	}

	return false, nil
}
