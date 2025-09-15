// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package auditing

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuditConfiguration contains information about the auditing service configuration.
type AuditConfiguration struct {
	metav1.TypeMeta

	// Backends are all the backends that will receive the audit logs.
	Backends []AuditBackend
}

// AuditBackend defines the configuration for a single audit backend.
// It specifies where audit events should be sent and how they should be delivered.
type AuditBackend struct {
	// HTTP specifies the configuration for an HTTP-based audit backend.
	// When configured, audit events will be sent via HTTP to the specified endpoint.
	HTTP *BackendHTTP
}

// BackendHTTP defines the configuration for an HTTP audit backend.
// This backend sends audit events to a remote HTTP endpoint over HTTPS.
type BackendHTTP struct {
	// URL is the HTTP endpoint where audit events will be sent.
	// This should be a complete HTTPS URL including the protocol, host, and path.
	URL string
	// TLS contains the TLS configuration for secure communication with the HTTP backend.
	TLS TLSConfig
}

// TLSConfig defines the TLS configuration for secure communication.
type TLSConfig struct {
	// SecretReferenceName is the name reference that leads to a Secret containing the TLS configuration.
	SecretReferenceName string
}
