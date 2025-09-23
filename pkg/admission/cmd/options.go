// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	extensionscmdwebhook "github.com/gardener/gardener/extensions/pkg/webhook/cmd"

	secretvalidator "github.com/gardener/gardener-extension-auditing/pkg/admission/validator/secret"
	shootvalidator "github.com/gardener/gardener-extension-auditing/pkg/admission/validator/shoot"
)

// GardenWebhookSwitchOptions are the extensionscmdwebhook.SwitchOptions for the admission webhooks.
func GardenWebhookSwitchOptions() *extensionscmdwebhook.SwitchOptions {
	return extensionscmdwebhook.NewSwitchOptions(
		extensionscmdwebhook.Switch(shootvalidator.Name, shootvalidator.New),
		extensionscmdwebhook.Switch(secretvalidator.Name, secretvalidator.New),
	)
}
