// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	extensionscontextwebhook "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-auditing/pkg/constants"
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

			extension, extensionError := getAuditingExtension(ctx, e.client, newDeployment.Namespace)
			if extensionError != nil {
				return extensionError
			}

			if cluster.Shoot.DeletionTimestamp != nil && extension == nil {
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
				sha   = sha256.Sum256(data)
				short = hex.EncodeToString(sha[:])[:8]
			)

			if newDeployment.Annotations == nil {
				newDeployment.Annotations = map[string]string{}
			}
			newDeployment.Annotations[constants.AuditWebhookAnnotationKey] = short
			if template.Annotations == nil {
				template.Annotations = map[string]string{}
			}
			template.Annotations[constants.AuditWebhookAnnotationKey] = short
		}

		ensureAPIServerIsMutated(ps, c)
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
