// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/gardener-extension-auditing/pkg/apis/auditing"
	"github.com/gardener/gardener-extension-auditing/pkg/apis/auditing/validation"
)

var _ = Describe("ValidateAuditConfiguration", func() {
	var base auditing.AuditConfiguration

	BeforeEach(func() {
		base = auditing.AuditConfiguration{
			Backends: []auditing.AuditBackend{
				{
					HTTP: &auditing.BackendHTTP{
						URL: "https://example.com/audit",
						TLS: auditing.TLSConfig{SecretReferenceName: "audit-secret"},
					},
				},
			},
		}
	})

	It("should pass for a valid configuration", func() {
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).To(BeEmpty())
	})

	It("should error when no backends are specified", func() {
		base.Backends = nil
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).ToNot(BeEmpty())
		Expect(errs[0].Field).To(ContainSubstring("backends"))
	})

	It("should error when HTTP backend is nil", func() {
		base.Backends[0].HTTP = nil
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).ToNot(BeEmpty())
		Expect(errs[0].Field).To(ContainSubstring("http"))
	})

	It("should error for non-https scheme", func() {
		base.Backends[0].HTTP.URL = "http://example.com/audit"
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).ToNot(BeEmpty())
		Expect(errs[0].Error()).To(ContainSubstring("URL scheme must be 'https'"))
	})

	It("should error for empty URL", func() {
		base.Backends[0].HTTP.URL = ""
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).ToNot(BeEmpty())
	})

	It("should allow URL without explicit path", func() {
		base.Backends[0].HTTP.URL = "https://example.com"
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).To(BeEmpty())
	})

	It("should error for URL with query parameters", func() {
		base.Backends[0].HTTP.URL = "https://example.com/audit?foo=bar"
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).ToNot(BeEmpty())
		Expect(errs[0].Error()).To(ContainSubstring("must not contain query parameters"))
	})

	It("should error for URL with fragment", func() {
		base.Backends[0].HTTP.URL = "https://example.com/audit#section"
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).ToNot(BeEmpty())
		Expect(errs[0].Error()).To(ContainSubstring("must not contain fragments"))
	})

	It("should error for URL with user info", func() {
		base.Backends[0].HTTP.URL = "https://user@example.com/audit"
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).ToNot(BeEmpty())
		Expect(errs[0].Error()).To(ContainSubstring("must not contain user information"))
	})

	It("should error for invalid secret reference name", func() {
		base.Backends[0].HTTP.TLS.SecretReferenceName = "Invalid_Name"
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).ToNot(BeEmpty())
		Expect(errs[0].Field).To(ContainSubstring("secretReferenceName"))
	})

	It("should detect duplicate backend URLs", func() {
		base.Backends = append(base.Backends, auditing.AuditBackend{HTTP: &auditing.BackendHTTP{URL: base.Backends[0].HTTP.URL, TLS: auditing.TLSConfig{SecretReferenceName: "audit-secret-2"}}})
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
			"Type":  Equal(field.ErrorTypeDuplicate),
			"Field": Equal("providerConfig.backends[1].http.url"),
		}))))
	})

	It("should allow valid gzip compression", func() {
		c := "gzip"
		base.Backends[0].HTTP.Compression = &c
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).To(BeEmpty())
	})

	It("should reject unsupported compression", func() {
		c := "brotli"
		base.Backends[0].HTTP.Compression = &c
		errs := validation.ValidateAuditConfiguration(&base, field.NewPath("providerConfig"))
		Expect(errs).ToNot(BeEmpty())
		Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
			"Type":   Equal(field.ErrorTypeNotSupported),
			"Field":  Equal("providerConfig.backends[0].http.compression"),
			"Detail": Equal("supported values: \"gzip\""),
		}))))
	})
})

var _ = Describe("ValidateBackendHTTPTLSSecret", func() {
	var secret *corev1.Secret
	var fldPath *field.Path

	BeforeEach(func() {
		fldPath = field.NewPath("providerConfig", "backends").Index(0).Child("http", "tls", "secretReferenceName")
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		template := x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.com"}}
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		Expect(err).NotTo(HaveOccurred())
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyBytes, err := x509.MarshalECPrivateKey(priv)
		Expect(err).NotTo(HaveOccurred())
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-secret", Namespace: "ns"},
			Data: map[string][]byte{
				"client.crt": certPEM,
				"client.key": keyPEM,
			},
		}
	})

	It("should succeed with full secret", func() {
		errs := validation.ValidateBackendHTTPTLSSecret(secret, fldPath, "tls-secret")
		Expect(errs).To(BeEmpty())
	})

	It("should succeed without optional ca.crt", func() {
		delete(secret.Data, "ca.crt")
		errs := validation.ValidateBackendHTTPTLSSecret(secret, fldPath, "tls-secret")
		Expect(errs).To(BeEmpty())
	})

	It("should error missing client.crt", func() {
		delete(secret.Data, "client.crt")
		errs := validation.ValidateBackendHTTPTLSSecret(secret, fldPath, "tls-secret")
		Expect(errs).ToNot(BeEmpty())
	})

	It("should error missing client.key", func() {
		delete(secret.Data, "client.key")
		errs := validation.ValidateBackendHTTPTLSSecret(secret, fldPath, "tls-secret")
		Expect(errs).ToNot(BeEmpty())
	})

	It("should error on empty data entries", func() {
		secret.Data["client.crt"] = []byte("   ")
		secret.Data["client.key"] = []byte("")
		errs := validation.ValidateBackendHTTPTLSSecret(secret, fldPath, "tls-secret")
		Expect(errs).To(HaveLen(2))
	})

	It("should error on key mismatch", func() {
		otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		otherKeyBytes, err := x509.MarshalECPrivateKey(otherPriv)
		Expect(err).NotTo(HaveOccurred())
		secret.Data["client.key"] = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: otherKeyBytes})
		errs := validation.ValidateBackendHTTPTLSSecret(secret, fldPath, "tls-secret")
		Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
			"Type":   Equal(field.ErrorTypeInvalid),
			"Field":  Equal("providerConfig.backends[0].http.tls.secretReferenceName"),
			"Detail": ContainSubstring("client.key does not match"),
		}))))
	})

	It("should error on invalid certificate PEM", func() {
		secret.Data["client.crt"] = []byte("-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----")
		errs := validation.ValidateBackendHTTPTLSSecret(secret, fldPath, "tls-secret")
		Expect(errs).ToNot(BeEmpty())
	})

	It("should error on invalid key PEM", func() {
		secret.Data["client.key"] = []byte("-----BEGIN EC PRIVATE KEY-----\nINVALID\n-----END EC PRIVATE KEY-----")
		errs := validation.ValidateBackendHTTPTLSSecret(secret, fldPath, "tls-secret")
		Expect(errs).ToNot(BeEmpty())
	})
})
