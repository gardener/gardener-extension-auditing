// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-auditing/pkg/constants"
)

const (
	// Name is a name for a validation webhook.
	Name = "auditing-shoot-validator"
)

var logger = log.Log.WithName("auditing-shoot-validator-webhook")

// New creates a new webhook that validates Shoot and Secret resources.
func New(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Setting up webhook", "name", Name)

	decoder := serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder()
	apiReader := mgr.GetAPIReader()

	return extensionswebhook.New(mgr, extensionswebhook.Args{
		Provider: constants.ExtensionType,
		Name:     Name,
		Path:     "/webhooks/auditing/shoot",
		Validators: map[extensionswebhook.Validator][]extensionswebhook.Type{
			NewShootValidator(apiReader, decoder): {{Obj: &core.Shoot{}}},
		},
		Target: extensionswebhook.TargetSeed,
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"extensions.extensions.gardener.cloud/auditing": "true"},
		},
	})
}
