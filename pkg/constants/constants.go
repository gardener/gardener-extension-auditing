// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package constants

const (
	// ExtensionType is the name of the extension type.
	ExtensionType = "auditing"
	// ServiceName is the name of the service.
	ServiceName = "auditing"

	// ApplicationName is the name for resource describing the components deployed by the extension controller.
	ApplicationName = "auditing"

	// AuditlogForwarder is the name for resource describing the components deployed by the extension controller.
	AuditlogForwarder = "auditlog-forwarder"

	// AuditlogForwarderTLSSecretName is the name of the TLS secret resource used by the auditlog proxy in the seed cluster.
	AuditlogForwarderTLSSecretName = AuditlogForwarder + "-tls"
	// // ProxyTLSCertDir is the directory used for mounting the auditlog proxy webhook certificates.
	// ProxyTLSCertDir = "/var/run/auditlog-proxy/tls"

	// AuditWebhookKubeConfigSecretName is the name of the secret used bu the kube-apiserver to connect to the auditlog proxy.
	AuditWebhookKubeConfigSecretName = AuditlogForwarder + "-webhook-kubeconfig"
	// AuditWebhookConfigDir is the directory used for mounting the auditlog proxy kubeconfig used by the kube-apiserver.
	AuditWebhookConfigDir = "/var/run/secrets/audit-webhook"
	// AuditWebhookCADir is the directory used for mounting the auditlog proxy CA used by the kube-apiserver.
	AuditWebhookCADir = "/var/run/secrets/audit-webhook-ca"
)
