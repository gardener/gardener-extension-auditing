// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"context"
	"fmt"
	"slices"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-auditing/pkg/apis/auditing"
	auditingvalidation "github.com/gardener/gardener-extension-auditing/pkg/apis/auditing/validation"
	"github.com/gardener/gardener-extension-auditing/pkg/constants"
)

type secret struct {
	apiReader client.Reader
	decoder   runtime.Decoder
}

// NewSecretValidator returns a new instance of a secret validator.
func NewSecretValidator(apiReader client.Reader, decoder runtime.Decoder) extensionswebhook.Validator {
	return &secret{
		apiReader: apiReader,
		decoder:   decoder,
	}
}

// Validate validates the given secret object
func (s *secret) Validate(ctx context.Context, newObj, _ client.Object) error {
	secret, ok := newObj.(*corev1.Secret)
	if !ok {
		return fmt.Errorf("wrong object type %T", newObj)
	}

	// List shoots in the same namespace.
	shootList := &gardencorev1beta1.ShootList{}
	if err := s.apiReader.List(ctx, shootList, client.InNamespace(secret.Namespace)); err != nil {
		return fmt.Errorf("unable to list shoots in namespace %s: %w", secret.Namespace, err)
	}

	// Iterate shoots, find those with auditing extension enabled, decode config, collect referenced secret names.
	for _, shoot := range shootList.Items {
		// Find auditing extension entry.
		idx := slices.IndexFunc(shoot.Spec.Extensions, func(e gardencorev1beta1.Extension) bool { return e.Type == constants.ExtensionType })
		if idx == -1 {
			continue
		}

		ext := shoot.Spec.Extensions[idx]
		if ext.ProviderConfig == nil { // invalid shoot; skip (shoot webhook should catch)
			continue
		}

		auditConfig := &auditing.AuditConfiguration{}
		if err := runtime.DecodeInto(s.decoder, ext.ProviderConfig.Raw, auditConfig); err != nil {
			return fmt.Errorf("failed to decode auditing providerConfig for shoot %s/%s: %w", shoot.Namespace, shoot.Name, err)
		}

		for _, backend := range auditConfig.Backends {
			switch {
			case backend.HTTP != nil:
				refName := backend.HTTP.TLS.SecretReferenceName
				if refName == "" { // no reference; invalid config; skip (shoot webhook should catch)
					continue
				}

				secretName, err := getReferencedSecretName(shoot, refName)
				if err != nil {
					continue // invalid reference; skip (shoot webhook should catch)
				}

				if secretName == secret.Name {
					fldPath := field.NewPath("data")
					errs := auditingvalidation.ValidateBackendHTTPTLSSecret(secret, fldPath, refName)
					if len(errs) > 0 {
						return errs.ToAggregate()
					}
					return nil
				}
			default:
				// do nothing
			}
		}
	}

	return nil
}

// getReferencedSecretName returns the name of the referenced secret that matches the secret reference name.
func getReferencedSecretName(shoot gardencorev1beta1.Shoot, secretReferenceName string) (string, error) {
	for _, ref := range shoot.Spec.Resources {
		if ref.Name == secretReferenceName {
			if ref.ResourceRef.Kind != "Secret" {
				return "", fmt.Errorf("invalid referenced resource, expected kind Secret, not %s: %s", ref.ResourceRef.Kind, ref.ResourceRef.Name)
			}
			return ref.ResourceRef.Name, nil
		}
	}

	return "", fmt.Errorf("missing or invalid referenced resource: %s", secretReferenceName)
}
