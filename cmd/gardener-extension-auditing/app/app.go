// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	extensionsheartbeatcontroller "github.com/gardener/gardener/extensions/pkg/controller/heartbeat"
	"github.com/gardener/gardener/extensions/pkg/util"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	gardenerhealthz "github.com/gardener/gardener/pkg/healthz"
	"github.com/gardener/gardener/pkg/logger"
	"github.com/go-logr/logr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringv1alpha1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1alpha1"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	componentbaseconfigv1alpha1 "k8s.io/component-base/config/v1alpha1"
	"k8s.io/component-base/version"
	"k8s.io/component-base/version/verflag"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	auditinstall "github.com/gardener/gardener-extension-auditing/pkg/apis/auditing/install"
	auditcontroller "github.com/gardener/gardener-extension-auditing/pkg/controller/audit"
	apiserverwebhook "github.com/gardener/gardener-extension-auditing/pkg/webhook/apiserver"
)

// NewAuditControllerCommand creates a new command that is used to start the auditing service controller.
func NewAuditControllerCommand() *cobra.Command {
	options := NewOptions()

	cmd := &cobra.Command{
		Use:           "auditing",
		Short:         "Audit controller manages audit logging within a shoot or garden.",
		SilenceErrors: true,

		RunE: func(cmd *cobra.Command, _ []string) error {
			verflag.PrintAndExitIfRequested()

			logLevel, logFormat := "info", "json"
			log, err := logger.NewZapLogger(logLevel, logFormat)
			if err != nil {
				return fmt.Errorf("error instantiating zap logger: %w", err)
			}

			log = log.WithName("gardener-extension-auditing") // TODO: do we need to name the logger?
			logf.SetLogger(log)
			klog.SetLogger(log)

			log.Info("Starting audit", "version", version.Get())

			if err := options.optionAggregator.Complete(); err != nil {
				return fmt.Errorf("error completing options: %w", err)
			}

			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				log.Info("Flag", "name", flag.Name, "value", flag.Value, "default", flag.DefValue)
			})

			if err := options.heartbeatOptions.Validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true
			return options.run(cmd.Context(), log)
		},
	}

	verflag.AddFlags(cmd.Flags())
	options.optionAggregator.AddFlags(cmd.Flags())

	return cmd
}

func (o *Options) run(ctx context.Context, log logr.Logger) error {
	// TODO: Make these flags configurable via command line parameters or component config file.
	util.ApplyClientConnectionConfigurationToRESTConfig(&componentbaseconfigv1alpha1.ClientConnectionConfiguration{
		QPS:   100.0,
		Burst: 130,
	}, o.restOptions.Completed().Config)

	mgrOpts := o.managerOptions.Completed().Options()
	mgrOpts.Logger = log

	mgrOpts.Client = client.Options{
		Cache: &client.CacheOptions{
			DisableFor: []client.Object{
				&corev1.Secret{},    // applied for ManagedResources
				&corev1.ConfigMap{}, // applied for monitoring config
			},
		},
	}

	mgr, err := manager.New(o.restOptions.Completed().Config, mgrOpts)
	if err != nil {
		return fmt.Errorf("could not instantiate controller-manager: %w", err)
	}

	if err := operatorv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %s", err)
	}

	if err := extensionscontroller.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %w", err)
	}

	if err := monitoringv1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %w", err)
	}
	if err := monitoringv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %w", err)
	}

	if err := auditinstall.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %s", err)
	}

	ctrlConfig := o.auditOptions.Completed()
	ctrlConfig.Apply(&auditcontroller.DefaultAddOptions.Config)
	o.controllerOptions.Completed().Apply(&auditcontroller.DefaultAddOptions.ControllerOptions)
	o.reconcileOptions.Completed().Apply(&auditcontroller.DefaultAddOptions.IgnoreOperationAnnotation, &auditcontroller.DefaultAddOptions.ExtensionClasses)
	o.heartbeatOptions.Completed().Apply(&extensionsheartbeatcontroller.DefaultAddOptions)

	apiserverwebhook.DefaultAddOptions.ExtensionClasses = o.reconcileOptions.Completed().ExtensionClasses

	if err := o.controllerSwitches.Completed().AddToManager(ctx, mgr); err != nil {
		return fmt.Errorf("could not add controllers to manager: %w", err)
	}

	if _, err := o.webhookOptions.Completed().AddToManager(ctx, mgr, nil); err != nil {
		return fmt.Errorf("could not add the mutating webhook to manager: %w", err)
	}

	if err := mgr.AddHealthzCheck("informer-sync", gardenerhealthz.NewCacheSyncHealthzWithDeadline(mgr.GetLogger(), clock.RealClock{}, mgr.GetCache(), gardenerhealthz.DefaultCacheSyncDeadline)); err != nil {
		return fmt.Errorf("could not add ready check for informers: %w", err)
	}
	if err := mgr.AddReadyzCheck("informer-sync", gardenerhealthz.NewCacheSyncHealthz(mgr.GetCache())); err != nil {
		return fmt.Errorf("could not add ready check for informers: %w", err)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("could not add health check to manager: %w", err)
	}

	if err := mgr.AddReadyzCheck("webhook-server", mgr.GetWebhookServer().StartedChecker()); err != nil {
		return fmt.Errorf("could not add ready check for webhook server to manager: %w", err)
	}

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("error running manager: %w", err)
	}

	return nil
}
