// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-auditing/pkg/constants"
)

var _ extensionswebhook.Mutator = (*APIServerMutator)(nil)

type APIServerMutator struct {
	client client.Client
	logger logr.Logger
}

func NewAPIServerMutator(client client.Client, logger logr.Logger) *APIServerMutator {
	return &APIServerMutator{
		client: client,
		logger: logger,
	}
}

func (m *APIServerMutator) Mutate(ctx context.Context, newObj, _ client.Object) error {
	newDeployment, ok := newObj.(*appsv1.Deployment)
	if !ok {
		return fmt.Errorf("wrong object type, expected: *appsv1.Deployment, got: %T", newObj)
	}

	m.logger.Info("Mutating deployment", "key", client.ObjectKeyFromObject(newDeployment))

	// As we do not rely on namespace labels to identify whether the auditing extension is
	// installed, we need to check for the existence of the extension resource here.
	extension, extensionError := getAuditingExtension(ctx, m.client, newDeployment.Namespace)
	if extensionError != nil {
		return extensionError
	}

	if extension == nil || extension.DeletionTimestamp != nil {
		m.logger.Info("Skipping mutation as no auditing extension exists or is being deleted", "key", client.ObjectKeyFromObject(newDeployment))
		return nil
	}

	var (
		template   = &newDeployment.Spec.Template
		ps         = &template.Spec
		containers []*corev1.Container
	)

	for _, name := range []string{v1beta1constants.DeploymentNameKubeAPIServer, "gardener-apiserver"} {
		if c := extensionswebhook.ContainerWithName(ps.Containers, name); c != nil {
			containers = append(containers, c)
		}
	}

	for _, c := range containers {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: constants.AuditWebhookKubeConfigSecretName, Namespace: newDeployment.Namespace}}
		if err := m.client.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
			return err
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

		ensureKubeAPIServerIsMutated(ps, c)
	}

	return nil
}
