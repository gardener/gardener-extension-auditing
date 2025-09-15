// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/component/extensions/operatingsystemconfig/original/components/kubelet"
	oscutils "github.com/gardener/gardener/pkg/component/extensions/operatingsystemconfig/utils"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var logger = log.Log.WithName("auditing-kapiserver-webhook")

const (
	// WebhookName is the name of the kube-apiserver mutating webhook.
	WebhookName = "auditing"
)

// AddToManager creates a webhook with the default options and adds it to the manager.
func AddToManager(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Adding webhook to manager")

	fciCodec := oscutils.NewFileContentInlineCodec()

	mutator := genericmutator.NewMutator(
		mgr,
		NewEnsurer(mgr.GetClient(), logger),
		oscutils.NewUnitSerializer(),
		kubelet.NewConfigCodec(fciCodec),
		fciCodec,
		logger,
	)
	types := []extensionswebhook.Type{
		{Obj: &appsv1.Deployment{}},
	}

	handler, err := extensionswebhook.NewBuilder(mgr, logger).WithMutator(mutator, types...).Build()
	if err != nil {
		return nil, err
	}

	namespaceSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      v1beta1constants.LabelExtensionPrefix + "auditing",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"true"}},
		},
	}

	webhook := &extensionswebhook.Webhook{
		Name:              "auditlog",
		Provider:          "",
		Types:             types,
		Target:            extensionswebhook.TargetSeed,
		Path:              "auditlog",
		Webhook:           &admission.Webhook{Handler: handler},
		NamespaceSelector: namespaceSelector,
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				v1beta1constants.GardenRole: v1beta1constants.GardenRoleControlPlane,
				v1beta1constants.LabelApp:   v1beta1constants.LabelKubernetes,
				v1beta1constants.LabelRole:  v1beta1constants.LabelAPIServer,
			},
		},
	}

	return webhook, err
}
