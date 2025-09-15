// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"

	"github.com/gardener/gardener-extension-auditing/pkg/constants"
)

const (
	// ManagerIdentity is the identity used for the secrets manager.
	ManagerIdentity = "extension-" + constants.ServiceName
	// CAName is the name of the CA secret.
	CAName = "ca-extension-" + constants.ServiceName
)

// ConfigsFor returns configurations for the secrets manager for the given namespace.
func ConfigsFor(namespace string) []extensionssecretsmanager.SecretConfigWithOptions {
	return []extensionssecretsmanager.SecretConfigWithOptions{
		{
			Config: &secretsutils.CertificateSecretConfig{
				Name:       CAName,
				CommonName: CAName,
				CertType:   secretsutils.CACert,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.Persist()},
		},
		{
			Config: &secretsutils.CertificateSecretConfig{
				Name:                        constants.AuditlogForwarderTLSSecretName,
				CommonName:                  constants.AuditlogForwarder,
				DNSNames:                    kubernetesutils.DNSNamesForService(constants.AuditlogForwarder, namespace),
				CertType:                    secretsutils.ServerCert,
				SkipPublishingCACertificate: true,
			},
			// use old CA for signing server cert to prevent mismatches during auditlog-proxy and kube-apiserver upgrades
			// during the initial rotation phase
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(CAName)},
		},
		{
			Config: &secretsutils.CertificateSecretConfig{
				Name:                        constants.AuditlogForwarderClientTLSSecretName,
				CommonName:                  "kube-apiserver",
				CertType:                    secretsutils.ClientCert,
				SkipPublishingCACertificate: true,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(CAName, secretsmanager.UseCurrentCA)},
		},
	}
}
