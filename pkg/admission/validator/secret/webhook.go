// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-auditing/pkg/constants"
)

const (
	// Name is a name for a validation webhook.
	Name = "auditing-secret-validator"
)

var logger = log.Log.WithName("auditing-secret-validator-webhook")

// New creates a new webhook that validates Secret resources.
func New(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Setting up webhook", "name", Name)

	decoder := serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder()
	apiReader := mgr.GetAPIReader()

	return extensionswebhook.New(mgr, extensionswebhook.Args{
		Provider: constants.ExtensionType,
		Name:     Name,
		Path:     "/webhooks/auditing/secret",
		Validators: map[extensionswebhook.Validator][]extensionswebhook.Type{
			NewSecretValidator(apiReader, decoder): {{Obj: &corev1.Secret{}}},
		},
		Target: extensionswebhook.TargetSeed,
	})
}
