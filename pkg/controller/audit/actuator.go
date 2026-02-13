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
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	v1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1/helper"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	operatorv1alpha1helper "github.com/gardener/gardener/pkg/apis/operator/v1alpha1/helper"
	"github.com/gardener/gardener/pkg/component"
	"github.com/gardener/gardener/pkg/controllerutils"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-auditing/imagevector"
	"github.com/gardener/gardener-extension-auditing/pkg/apis/auditing"
	auditingvalidation "github.com/gardener/gardener-extension-auditing/pkg/apis/auditing/validation"
	"github.com/gardener/gardener-extension-auditing/pkg/apis/config"
	auditlogforwarder "github.com/gardener/gardener-extension-auditing/pkg/component/auditlog-forwarder"
	"github.com/gardener/gardener-extension-auditing/pkg/constants"
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

	var (
		// hibernated                  bool // TODO replicas
		secretsManager secretsmanager.Interface

		referencedResources []gardencorev1beta1.NamedResourceReference
		gardenerMetadata    map[string]string
		caRotationPhase     gardencorev1beta1.CredentialsRotationPhase

		// initialize SecretsManager based on Cluster object
		configs        = secrets.ConfigsFor(namespace)
		extensionClass = extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.Class)
	)

	switch extensionClass {
	case extensionsv1alpha1.ExtensionClassShoot:
		cluster, err := extensionscontroller.GetCluster(ctx, a.client, namespace)
		if err != nil {
			return fmt.Errorf("failed to get cluster: %w", err)
		}

		if v1beta1helper.HibernationIsEnabled(cluster.Shoot) {
			return nil
		}
		secretsManager, err = extensionssecretsmanager.SecretsManagerForCluster(
			ctx,
			log.WithName("secretsmanager"),
			clock.RealClock{},
			a.client,
			cluster,
			secrets.ManagerIdentity,
			configs,
		)
		if err != nil {
			return err
		}
		referencedResources = cluster.Shoot.Spec.Resources
		gardenerMetadata = map[string]string{
			"shoot.gardener.cloud/id":        string(cluster.Shoot.UID),
			"shoot.gardener.cloud/name":      cluster.Shoot.Name,
			"shoot.gardener.cloud/namespace": cluster.Shoot.Namespace,
			"seed.gardener.cloud/id":         string(cluster.Seed.UID),
			"seed.gardener.cloud/name":       cluster.Seed.Name,
		}
		caRotationPhase = v1beta1helper.GetShootCARotationPhase(cluster.Shoot.Status.Credentials)
	case extensionsv1alpha1.ExtensionClassGarden:
		garden, err := getGarden(ctx, a.client)
		if err != nil {
			return fmt.Errorf("failed to get garden: %w", err)
		}
		secretsManager, err = extensionssecretsmanager.SecretsManagerForGarden(
			ctx,
			log.WithName("secretsmanager"),
			clock.RealClock{},
			a.client,
			garden,
			secrets.ManagerIdentityRuntime,
			configs,
			namespace,
		)
		if err != nil {
			return err
		}
		referencedResources = garden.Spec.Resources
		gardenerMetadata = map[string]string{
			"garden.gardener.cloud/id":              string(garden.UID),
			"garden.gardener.cloud/name":            garden.Name,
			"garden.gardener.cloud/clusterIdentity": garden.Spec.VirtualCluster.Gardener.ClusterIdentity,
		}
		caRotationPhase = operatorv1alpha1helper.GetCARotationPhase(garden.Status.Credentials)
	default:
		return fmt.Errorf("unsupported extension class %q", extensionClass)
	}

	image, err := imagevector.ImageVector().FindImage("auditlog-forwarder")
	if err != nil {
		return fmt.Errorf("failed to find image for auditlog-forwarder: %w", err)
	}

	var outputs []auditlogforwarder.Output
	for _, backend := range auditConfig.Backends {
		refSecretName, err := lookupReferencedSecret(referencedResources, backend.HTTP.TLS.SecretReferenceName, extensionClass)
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
		Image:               image.String(),
		MetadataAnnotations: gardenerMetadata,
		AuditOutputs:        outputs,
		ExtensionClass:      extensionClass,
	})

	if err = forwarder.Deploy(ctx); err != nil {
		return fmt.Errorf("failed to deploy the auditlog-forwarder component: %w", err)
	}

	if err := forwarder.Wait(ctx); err != nil {
		return fmt.Errorf("failed to wait the auditlog-forwarder component to be healthy: %w", err)
	}

	if err := a.reconcileCABundleSecrets(ctx, log, namespace, secretsManager, caRotationPhase); err != nil {
		return err
	}

	if err := secretsManager.Cleanup(ctx); err != nil {
		return err
	}

	if extensionClass == extensionsv1alpha1.ExtensionClassGarden {
		// Patch the deployments for gardener and kube apiserver in order to trigger the mutating webhook.
		for _, name := range []string{"gardener-apiserver", operatorv1alpha1.DeploymentNameVirtualGardenKubeAPIServer} {
			depl := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
			}

			if err := a.client.Get(ctx, client.ObjectKeyFromObject(depl), depl); err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("Skip patching deployment as it does not exist", "key", client.ObjectKeyFromObject(depl))
					continue
				}
				return err
			}

			if depl.DeletionTimestamp != nil {
				log.Info("Skip patching deployment as it is being deleted", "key", client.ObjectKeyFromObject(depl))
				continue
			}

			if err := a.client.Patch(ctx, depl, client.RawPatch(types.StrategicMergePatchType, []byte("{}"))); err != nil {
				return err
			}
		}
	}

	return nil
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
	var (
		namespace      = ex.GetNamespace()
		extensionClass = extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.Class)
	)

	if extensionClass == extensionsv1alpha1.ExtensionClassGarden {
		// Patch the deployments for gardener and kube-apiserver in order to trigger webhook.
		for _, name := range []string{"gardener-apiserver", operatorv1alpha1.DeploymentNameVirtualGardenKubeAPIServer} {
			depl := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
			}

			if err := a.client.Get(ctx, client.ObjectKeyFromObject(depl), depl); err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("Skip patching deployment as it does not exist", "key", client.ObjectKeyFromObject(depl))
					continue
				}
				return err
			}

			if depl.DeletionTimestamp != nil {
				log.Info("Skip patching deployment as it is being deleted", "key", client.ObjectKeyFromObject(depl))
				continue
			}

			if _, ok := depl.Annotations[constants.AuditWebhookAnnotationKey]; !ok {
				log.Info("Skip patching deployment does not have audit webhook annotation", "key", client.ObjectKeyFromObject(depl))
				continue
			}

			patch := client.MergeFrom(depl.DeepCopy())
			delete(depl.Annotations, constants.AuditWebhookAnnotationKey)
			if c := extensionswebhook.ContainerWithName(depl.Spec.Template.Spec.Containers, v1beta1constants.DeploymentNameKubeAPIServer); c != nil {
				c.Args = extensionswebhook.EnsureNoStringWithPrefix(c.Args, "--audit-webhook-")
			}

			if err := a.client.Patch(ctx, depl, patch); err != nil {
				return err
			}
		}
	}

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

	var secretsManager secretsmanager.Interface
	switch extensionClass {
	case extensionsv1alpha1.ExtensionClassShoot:
		cluster, err := extensionscontroller.GetCluster(ctx, a.client, namespace)
		if err != nil {
			return fmt.Errorf("failed to get cluster: %w", err)
		}

		secretsManager, err = extensionssecretsmanager.SecretsManagerForCluster(ctx, log.WithName("secretsmanager"), clock.RealClock{}, a.client, cluster, secrets.ManagerIdentity, nil)
		if err != nil {
			return err
		}
	case extensionsv1alpha1.ExtensionClassGarden:
		garden, err := getGarden(ctx, a.client)
		if err != nil {
			return fmt.Errorf("failed to get garden: %w", err)
		}

		configs := secrets.ConfigsFor(namespace)
		secretsManager, err = extensionssecretsmanager.SecretsManagerForGarden(
			ctx,
			log.WithName("secretsmanager"),
			clock.RealClock{},
			a.client,
			garden,
			secrets.ManagerIdentityRuntime,
			configs,
			namespace,
		)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported extension class %q", extensionClass)
	}

	if err := secretsManager.Cleanup(ctx); err != nil {
		return err
	}

	return nil
}

// reconcileCABundleSecrets is responsible to retain old CA bundle secrets as long as they are needed.
// Secret retention is controlled via addition or removal of finalizer on the CA bundle secrets.
// During credentials rotation, new CA bundle secret is generated and the old one is removed
// when secretsManager.Cleanup() is called. However, the old bundle secret is still in use
// by the kube-apiserver deployment which is not yet reconciled by gardenlet or gardener operator.
// The new bundle secret is generated during the `Preparing` and `Completing` phases but used a bit later
// during the shoot/garden reconciliation flow, therefore during these phases the old bundle secrets
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

func lookupReferencedSecret(referencedResources []gardencorev1beta1.NamedResourceReference, refname string, extensionClass extensionsv1alpha1.ExtensionClass) (string, error) {
	for _, ref := range referencedResources {
		if ref.Name == refname {
			if ref.ResourceRef.Kind != "Secret" {
				err := fmt.Errorf("invalid referenced resource, expected kind Secret, not %s: %s", ref.ResourceRef.Kind, ref.ResourceRef.Name)
				return "", err
			}
			prefix := ""
			if extensionClass == extensionsv1alpha1.ExtensionClassShoot {
				prefix = v1beta1constants.ReferencedResourcesPrefix
			}
			return prefix + ref.ResourceRef.Name, nil
		}
	}
	return "", fmt.Errorf("missing or invalid referenced resource: %s", refname)
}

func getGarden(ctx context.Context, client client.Client) (*operatorv1alpha1.Garden, error) {
	gardenList := &operatorv1alpha1.GardenList{}
	if err := client.List(ctx, gardenList); err != nil {
		return nil, fmt.Errorf("failed to list gardens: %w", err)
	}
	if len(gardenList.Items) == 0 {
		return nil, fmt.Errorf("no gardens found in cluster")
	}
	if len(gardenList.Items) > 1 {
		return nil, fmt.Errorf("multiple gardens found, only one is supported")
	}

	return &gardenList.Items[0], nil
}
