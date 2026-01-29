// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"

	extensionscmdcontroller "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	extensionsheartbeatcmd "github.com/gardener/gardener/extensions/pkg/controller/heartbeat/cmd"
	extensionscmdwebhook "github.com/gardener/gardener/extensions/pkg/webhook/cmd"

	auditcmd "github.com/gardener/gardener-extension-auditing/pkg/cmd"
)

// ExtensionName is the name of the extension.
const ExtensionName = "extension-auditing"

// Options holds configuration passed to the auditing service controller.
type Options struct {
	generalOptions     *extensionscmdcontroller.GeneralOptions
	auditOptions       *auditcmd.AuditOptions
	restOptions        *extensionscmdcontroller.RESTOptions
	managerOptions     *extensionscmdcontroller.ManagerOptions
	controllerOptions  *extensionscmdcontroller.ControllerOptions
	heartbeatOptions   *extensionsheartbeatcmd.Options
	controllerSwitches *extensionscmdcontroller.SwitchOptions
	reconcileOptions   *extensionscmdcontroller.ReconcilerOptions
	webhookOptions     *extensionscmdwebhook.AddToManagerOptions
	optionAggregator   extensionscmdcontroller.OptionAggregator
}

// NewOptions creates a new Options instance.
func NewOptions() *Options {
	// options for the webhook server
	webhookServerOptions := &extensionscmdwebhook.ServerOptions{
		Namespace: os.Getenv("WEBHOOK_CONFIG_NAMESPACE"),
	}

	webhookSwitches := auditcmd.WebhookSwitchOptions()
	webhookOptions := extensionscmdwebhook.NewAddToManagerOptions(
		"auditing",
		"",
		nil,
		nil,
		webhookServerOptions,
		webhookSwitches,
	)

	options := &Options{
		generalOptions: &extensionscmdcontroller.GeneralOptions{},
		auditOptions:   &auditcmd.AuditOptions{},
		restOptions:    &extensionscmdcontroller.RESTOptions{},
		managerOptions: &extensionscmdcontroller.ManagerOptions{
			// These are default values.
			LeaderElection:          true,
			LeaderElectionID:        extensionscmdcontroller.LeaderElectionNameID(ExtensionName),
			LeaderElectionNamespace: os.Getenv("LEADER_ELECTION_NAMESPACE"),
			WebhookServerPort:       443,
			WebhookCertDir:          "/tmp/gardener-extensions-cert",
			MetricsBindAddress:      ":8080",
			HealthBindAddress:       ":8081",
		},
		controllerOptions: &extensionscmdcontroller.ControllerOptions{
			// This is a default value.
			MaxConcurrentReconciles: 5,
		},
		heartbeatOptions: &extensionsheartbeatcmd.Options{
			// This is a default value.
			ExtensionName:        ExtensionName,
			RenewIntervalSeconds: 30,
			Namespace:            os.Getenv("LEADER_ELECTION_NAMESPACE"),
		},
		controllerSwitches: auditcmd.ControllerSwitches(),
		reconcileOptions:   &extensionscmdcontroller.ReconcilerOptions{},
		webhookOptions:     webhookOptions,
	}

	options.optionAggregator = extensionscmdcontroller.NewOptionAggregator(
		options.generalOptions,
		options.restOptions,
		options.managerOptions,
		options.controllerOptions,
		options.auditOptions,
		extensionscmdcontroller.PrefixOption("heartbeat-", options.heartbeatOptions),
		options.controllerSwitches,
		options.reconcileOptions,
		options.webhookOptions,
	)

	return options
}
