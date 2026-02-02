// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"context"
	"fmt"
	"slices"
	"strings"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
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

func getAuditingExtension(ctx context.Context, c client.Client, namespace string, class extensionsv1alpha1.ExtensionClass) (*extensionsv1alpha1.Extension, error) {
	extensions := extensionsv1alpha1.ExtensionList{}
	if err := c.List(ctx, &extensions, client.InNamespace(namespace)); err != nil {
		return nil, err
	}

	for _, extension := range extensions.Items {
		extensionClass := ptr.Deref(extension.Spec.Class, extensionsv1alpha1.ExtensionClassShoot)
		if extension.Spec.Type == constants.ExtensionType && extensionClass == class {
			return &extension, nil
		}
	}

	return nil, nil
}

// ensureAPIServerIsMutated ensures that the kube-apiserver or gardener-apiserver deployment is mutated accordingly
// so that it is able to communicate with the auditlog-forwarder.
func ensureAPIServerIsMutated(ps *corev1.PodSpec, c *corev1.Container) {
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
