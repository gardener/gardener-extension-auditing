// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package extension

import (
	"context"
	"fmt"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	v1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/component"
	"github.com/gardener/gardener/pkg/controllerutils"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-auditing/imagevector"
	"github.com/gardener/gardener-extension-auditing/pkg/apis/auditing"
	auditingvalidation "github.com/gardener/gardener-extension-auditing/pkg/apis/auditing/validation"
	"github.com/gardener/gardener-extension-auditing/pkg/apis/config"
	auditlogforwarder "github.com/gardener/gardener-extension-auditing/pkg/component/auditlog-forwarder"
	"github.com/gardener/gardener-extension-auditing/pkg/secrets"
)

// NewActuator returns an actuator responsible for audit Extension resources.
func NewActuator(client client.Client, reader client.Reader, decoder runtime.Decoder, config config.Configuration) extension.Actuator {
	return &actuator{
		client:  client,
		reader:  reader,
		decoder: decoder,
		config:  config,
	}
}

type actuator struct {
	client  client.Client
	reader  client.Reader
	decoder runtime.Decoder
	config  config.Configuration
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()
	cluster, err := extensionscontroller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return fmt.Errorf("failed to get cluster: %w", err)
	}

	if v1beta1helper.HibernationIsEnabled(cluster.Shoot) {
		return nil
	}

	if ex.Spec.ProviderConfig == nil {
		return fmt.Errorf("providerConfig is required for the audit extension")
	}

	auditConfig := &auditing.AuditConfiguration{}
	if err := runtime.DecodeInto(a.decoder, ex.Spec.ProviderConfig.Raw, auditConfig); err != nil {
		return fmt.Errorf("failed to decode providerConfig: %w", err)
	}

	if errs := auditingvalidation.ValidateAuditConfiguration(auditConfig, field.NewPath("providerConfig")); len(errs) > 0 {
		return fmt.Errorf("invalid audit configuration: %w", errs.ToAggregate())
	}

	configs := secrets.ConfigsFor(namespace)
	secretsManager, err := extensionssecretsmanager.SecretsManagerForCluster(ctx, log.WithName("secretsmanager"), clock.RealClock{}, a.client, cluster, secrets.ManagerIdentity, configs)
	if err != nil {
		return err
	}

	image, err := imagevector.ImageVector().FindImage("auditlog-forwarder")
	if err != nil {
		return fmt.Errorf("failed to find image for auditlog-forwarder: %w", err)
	}

	var outputs []auditlogforwarder.Output
	for _, backend := range auditConfig.Backends {
		refSecretName, err := lookupReferencedSecret(cluster, backend.HTTP.TLS.SecretReferenceName)
		if err != nil {
			return err
		}

		refSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      refSecretName,
				Namespace: ex.Namespace,
			},
		}
		if err = a.client.Get(ctx, client.ObjectKeyFromObject(refSecret), refSecret); err != nil {
			return err
		}

		// TODO validate secret data

		_, refSecretContainsCABundle := refSecret.Data["ca.crt"]
		outputs = append(outputs, auditlogforwarder.Output{
			HTTP: &auditlogforwarder.OutputHTTP{
				URL:                       backend.HTTP.URL,
				TLSSecretName:             refSecretName,
				TLSSecretContainsCABundle: refSecretContainsCABundle,
				Compression:               backend.HTTP.Compression,
			},
		})
	}

	forwarder := auditlogforwarder.New(a.client, a.reader, namespace, secretsManager, auditlogforwarder.Values{
		Image: image.String(),
		Metadata: auditlogforwarder.GardenerMetadata{
			ShootMetadata: auditlogforwarder.ShootMetadata{
				ID:        string(cluster.Shoot.UID),
				Name:      cluster.Shoot.Name,
				Namespace: cluster.Shoot.Namespace,
			},
			SeedMetadata: auditlogforwarder.SeedMetadata{
				ID:   string(cluster.Seed.UID),
				Name: cluster.Seed.Name,
			},
		},
		AuditOutputs: outputs,
	})

	if err = forwarder.Deploy(ctx); err != nil {
		return fmt.Errorf("failed to deploy the auditlog-forwarder component: %w", err)
	}

	if err := forwarder.Wait(ctx); err != nil {
		return fmt.Errorf("failed to wait the auditlog-forwarder component to be healthy: %w", err)
	}

	if err := a.reconcileCABundleSecrets(ctx, log, namespace, secretsManager, v1beta1helper.GetShootCARotationPhase(cluster.Shoot.Status.Credentials)); err != nil {
		return err
	}

	return secretsManager.Cleanup(ctx)
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.delete(ctx, log, ex, false, false)
}

// Restore the Extension resource.
func (a *actuator) Restore(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, log, ex)
}

// Migrate the Extension resource.
func (a *actuator) Migrate(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.delete(ctx, log, ex, true, false)
}

// ForceDelete the Extension resource.
//
// We don't need to wait for the ManagedResource deletion because ManagedResources are finalized by gardenlet
// in later step in the Shoot force deletion flow.
func (a *actuator) ForceDelete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.delete(ctx, log, ex, false, true)
}

func (a *actuator) delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension, skipSecretsManagerSecrets, forceDelete bool) error {
	namespace := ex.GetNamespace()

	forwarder := auditlogforwarder.New(a.client, a.reader, namespace, nil, auditlogforwarder.Values{})
	if !forceDelete {
		if err := component.OpDestroyAndWait(forwarder).Destroy(ctx); err != nil {
			return fmt.Errorf("failed to destroy the auditlog-forwarder component: %w", err)
		}
	} else {
		if err := forwarder.Destroy(ctx); err != nil {
			return fmt.Errorf("failed to destroy the auditlog-forwarder component: %w", err)
		}
	}

	const finalizer = extension.FinalizerPrefix + "/" + FinalizerSuffix
	caBundleSecrets := &corev1.SecretList{}
	if err := a.reader.List(ctx, caBundleSecrets, client.InNamespace(namespace), client.MatchingLabels{
		secretsmanager.LabelKeyManagedBy:       secretsmanager.LabelValueSecretsManager,
		secretsmanager.LabelKeyManagerIdentity: secrets.ManagerIdentity,
		secretsmanager.LabelKeyBundleFor:       secrets.CAName,
	}); err != nil {
		return err
	}

	for _, s := range caBundleSecrets.Items {
		log.Info("Remove finalizer from CA bundle secret", "secret", client.ObjectKeyFromObject(&s))
		if err := controllerutils.RemoveFinalizers(ctx, a.client, &s, finalizer); err != nil {
			return err
		}
	}

	if skipSecretsManagerSecrets {
		return nil
	}

	cluster, err := extensionscontroller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return fmt.Errorf("failed to get cluster: %w", err)
	}

	secretsManager, err := extensionssecretsmanager.SecretsManagerForCluster(ctx, log.WithName("secretsmanager"), clock.RealClock{}, a.client, cluster, secrets.ManagerIdentity, nil)
	if err != nil {
		return err
	}

	return secretsManager.Cleanup(ctx)
}

// reconcileCABundleSecrets is responsible to retain old CA bundle secrets as long as they are needed.
// Secret retention is controlled via addition or removal of finalizer on the CA bundle secrets.
// During credentials rotation, new CA bundle secret is generated and the old one is removed
// when secretsManager.Cleanup() is called. However, the old bundle secret is still in use
// by the kube-apiserver deployment which is not yet reconciled by gardenlet.
// The new bundle secret is generated during the `Preparing` and `Completing` phases but used a bit later
// during the shoot reconciliation flow, therefore during these phases the old bundle secrets
// must be retained in the system by not removing their finalizers.
func (a *actuator) reconcileCABundleSecrets(ctx context.Context, log logr.Logger, namespace string, secretsManager secretsmanager.Interface, phase gardencorev1beta1.CredentialsRotationPhase) error {
	const finalizer = extension.FinalizerPrefix + "/" + FinalizerSuffix

	caBundle, found := secretsManager.Get(secrets.CAName, secretsmanager.Bundle)
	if !found {
		return fmt.Errorf("bundle secret for %q not found", secrets.CAName)
	}

	log.Info("Add finalizer to the current CA bundle secret", "secret", client.ObjectKeyFromObject(caBundle))
	if err := controllerutils.AddFinalizers(ctx, a.client, caBundle, finalizer); err != nil {
		return err
	}

	// Retain the old ca bundle secrets
	if phase == gardencorev1beta1.RotationPreparing || phase == gardencorev1beta1.RotationCompleting {
		log.Info("Skip removing the finalizer from the old CA bundle secrets", "phase", phase)
		return nil
	}

	caBundleSecrets := &corev1.SecretList{}
	if err := a.reader.List(ctx, caBundleSecrets, client.InNamespace(namespace), client.MatchingLabels{
		secretsmanager.LabelKeyManagedBy:       secretsmanager.LabelValueSecretsManager,
		secretsmanager.LabelKeyManagerIdentity: secrets.ManagerIdentity,
		secretsmanager.LabelKeyBundleFor:       secrets.CAName,
	}); err != nil {
		return err
	}

	for _, s := range caBundleSecrets.Items {
		if s.Name == caBundle.Name { // Skip current CA Bundle secret
			continue
		}

		log.Info("Remove finalizer from old CA bundle secret", "secret", client.ObjectKeyFromObject(&s))
		if err := controllerutils.RemoveFinalizers(ctx, a.client, &s, finalizer); err != nil {
			return err
		}
	}

	return nil
}

func lookupReferencedSecret(cluster *extensionscontroller.Cluster, refname string) (string, error) {
	if cluster.Shoot != nil {
		for _, ref := range cluster.Shoot.Spec.Resources {
			if ref.Name == refname {
				if ref.ResourceRef.Kind != "Secret" {
					err := fmt.Errorf("invalid referenced resource, expected kind Secret, not %s: %s", ref.ResourceRef.Kind, ref.ResourceRef.Name)
					return "", err
				}
				return v1beta1constants.ReferencedResourcesPrefix + ref.ResourceRef.Name, nil
			}
		}
	}
	return "", fmt.Errorf("missing or invalid referenced resource: %s", refname)
}
