// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"slices"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencore "github.com/gardener/gardener/pkg/apis/core"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-auditing/pkg/apis/auditing"
	auditingvalidation "github.com/gardener/gardener-extension-auditing/pkg/apis/auditing/validation"
	"github.com/gardener/gardener-extension-auditing/pkg/constants"
)

type shoot struct {
	apiReader client.Reader
	decoder   runtime.Decoder
}

// NewShootValidator returns a new instance of a shoot validator.
func NewShootValidator(apiReader client.Reader, decoder runtime.Decoder) extensionswebhook.Validator {
	return &shoot{
		apiReader: apiReader,
		decoder:   decoder,
	}
}

// Validate validates the given shoot object
func (s *shoot) Validate(ctx context.Context, newObj, _ client.Object) error {
	shoot, ok := newObj.(*gardencore.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", newObj)
	}

	i := slices.IndexFunc(shoot.Spec.Extensions, func(e gardencore.Extension) bool {
		return e.Type == constants.ExtensionType
	})
	if i == -1 {
		return nil
	}

	ext := shoot.Spec.Extensions[i]

	providerConfigPath := field.NewPath("spec", "extensions").Index(i).Child("providerConfig")
	if ext.ProviderConfig == nil {
		return field.Required(providerConfigPath, "providerConfig is required for the auditing extension")
	}

	auditConfig := &auditing.AuditConfiguration{}
	if err := runtime.DecodeInto(s.decoder, ext.ProviderConfig.Raw, auditConfig); err != nil {
		return fmt.Errorf("failed to decode providerConfig: %w", err)
	}

	allErrs := field.ErrorList{}

	allErrs = append(allErrs, auditingvalidation.ValidateAuditConfiguration(auditConfig, providerConfigPath)...)
	for i, backend := range auditConfig.Backends {
		backendPath := providerConfigPath.Child("backends").Index(i)

		if backend.HTTP != nil {
			secretRefName := backend.HTTP.TLS.SecretReferenceName

			secretName, err := getReferencedSecretName(shoot, secretRefName)
			if err != nil {
				allErrs = append(allErrs, field.Invalid(backendPath.Child("http", "tls", "secretReferenceName"), secretRefName, fmt.Sprintf("failed to determine referenced secret %q: %v", secretRefName, err)))
				continue
			}

			secret := &corev1.Secret{}
			secretKey := client.ObjectKey{Name: secretName, Namespace: shoot.Namespace}
			if err := s.apiReader.Get(ctx, secretKey, secret); err != nil {
				allErrs = append(allErrs, field.Invalid(backendPath.Child("http", "tls", "secretReferenceName"), secretRefName, fmt.Sprintf("failed to retrieve referenced secret %q: %v", secretName, err)))
				continue
			}

			secretValidationErrs := auditingvalidation.ValidateBackendHTTPTLSSecret(secret, backendPath.Child("http", "tls", "secretReferenceName"), secretRefName)
			allErrs = append(allErrs, secretValidationErrs...)
		}
	}

	return allErrs.ToAggregate()
}

// getReferencedSecretName returns the name of the referenced secret that matches the secret reference name.
func getReferencedSecretName(shoot *gardencore.Shoot, secretReferenceName string) (string, error) {
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
