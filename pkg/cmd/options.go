// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"os"

	"github.com/gardener/gardener/extensions/pkg/controller/cmd"
	extensionshealthcheckcontroller "github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	extensionsheartbeatcontroller "github.com/gardener/gardener/extensions/pkg/controller/heartbeat"
	extensionscmdwebhook "github.com/gardener/gardener/extensions/pkg/webhook/cmd"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	apisconfig "github.com/gardener/gardener-extension-auditing/pkg/apis/config"
	"github.com/gardener/gardener-extension-auditing/pkg/apis/config/v1alpha1"
	"github.com/gardener/gardener-extension-auditing/pkg/apis/config/validation"
	auditcontroller "github.com/gardener/gardener-extension-auditing/pkg/controller/audit"
	healthcheckcontroller "github.com/gardener/gardener-extension-auditing/pkg/controller/healthcheck"
	kapiwebhook "github.com/gardener/gardener-extension-auditing/pkg/webhook/kapiserver"
)

var (
	scheme  *runtime.Scheme
	decoder runtime.Decoder
)

func init() {
	scheme = runtime.NewScheme()
	utilruntime.Must(apisconfig.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	decoder = serializer.NewCodecFactory(scheme).UniversalDecoder()
}

// AuditOptions holds options related to the auditing service.
type AuditOptions struct {
	ConfigLocation string
	config         *AuditServiceConfig
}

// AddFlags implements Flagger.AddFlags.
func (o *AuditOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.ConfigLocation, "config", "", "Path to auditing service configuration")
}

// Complete implements Completer.Complete.
func (o *AuditOptions) Complete() error {
	if o.ConfigLocation == "" {
		return errors.New("config location is not set")
	}
	data, err := os.ReadFile(o.ConfigLocation)
	if err != nil {
		return err
	}

	config := apisconfig.Configuration{}
	if err := runtime.DecodeInto(decoder, data, &config); err != nil {
		return err
	}

	if errs := validation.ValidateConfiguration(&config); len(errs) > 0 {
		return errs.ToAggregate()
	}

	o.config = &AuditServiceConfig{
		config: config,
	}

	return nil
}

// Completed returns the decoded AuditServiceConfiguration instance. Only call this if `Complete` was successful.
func (o *AuditOptions) Completed() *AuditServiceConfig {
	return o.config
}

// AuditServiceConfig contains configuration information about the auditing service.
type AuditServiceConfig struct {
	config apisconfig.Configuration
}

// Apply applies the AuditOptions to the passed ControllerOptions instance.
func (c *AuditServiceConfig) Apply(config *apisconfig.Configuration) {
	*config = c.config
}

// ControllerSwitches are the cmd.SwitchOptions for the provider controllers.
func ControllerSwitches() *cmd.SwitchOptions {
	return cmd.NewSwitchOptions(
		cmd.Switch(auditcontroller.ControllerName, auditcontroller.AddToManager),
		cmd.Switch(extensionshealthcheckcontroller.ControllerName, healthcheckcontroller.AddToManager),
		cmd.Switch(extensionsheartbeatcontroller.ControllerName, extensionsheartbeatcontroller.AddToManager),
	)
}

// WebhookSwitchOptions are the webhookcmd.SwitchOptions for the audit webhook.
func WebhookSwitchOptions() *extensionscmdwebhook.SwitchOptions {
	return extensionscmdwebhook.NewSwitchOptions(
		extensionscmdwebhook.Switch(kapiwebhook.WebhookName, kapiwebhook.AddToManager),
	)
}
