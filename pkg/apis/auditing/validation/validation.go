// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/gardener-extension-auditing/pkg/apis/auditing"
)

// ValidateAuditConfiguration validates an AuditConfiguration instance.
//
// The following invariants are enforced:
//   - At least one backend is defined.
//   - Each backend must specify its transport configuration (currently only HTTP is supported).
func ValidateAuditConfiguration(config *auditing.AuditConfiguration, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(config.Backends) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("backends"), "at least one backend must be provided"))
	}

	seenBackendSignatures := sets.New[string]()
	for i, backend := range config.Backends {
		backendFldPath := fldPath.Child("backends").Index(i)
		allErrs = append(allErrs, validateAuditBackend(backend, backendFldPath)...)

		// Simple duplicate detection for identical backend definitions (currently only HTTP URL uniqueness is relevant).
		if backend.HTTP != nil {
			sig := "http:" + backend.HTTP.URL
			if seenBackendSignatures.Has(sig) {
				allErrs = append(allErrs, field.Duplicate(backendFldPath.Child("http").Child("url"), backend.HTTP.URL))
			} else {
				seenBackendSignatures.Insert(sig)
			}
		}
	}

	return allErrs
}

// ValidateAuditConfigurationUpdate validates that the new configuration is a valid update from the old one.
func ValidateAuditConfigurationUpdate(_, newConfig *auditing.AuditConfiguration, fldPath *field.Path) field.ErrorList {
	return ValidateAuditConfiguration(newConfig, fldPath)
}

func validateAuditBackend(backend auditing.AuditBackend, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	if backend.HTTP == nil {
		allErrs = append(allErrs, field.Required(fldPath.Child("http"), "http backend configuration must be provided"))
		return allErrs
	}

	allErrs = append(allErrs, validateBackendHTTP(*backend.HTTP, fldPath.Child("http"))...)
	return allErrs
}

func validateBackendHTTP(httpCfg auditing.BackendHTTP, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	urlFld := fldPath.Child("url")
	if strings.TrimSpace(httpCfg.URL) == "" {
		allErrs = append(allErrs, field.Required(urlFld, "url must be specified"))
	} else {
		allErrs = append(allErrs, validateHTTPSURL(httpCfg.URL, urlFld)...)
	}

	tlsFld := fldPath.Child("tls")
	if strings.TrimSpace(httpCfg.TLS.SecretReferenceName) == "" {
		allErrs = append(allErrs, field.Required(tlsFld.Child("secretReferenceName"), "secret reference name must be specified"))
	} else {
		for _, msg := range apivalidation.NameIsDNSSubdomain(httpCfg.TLS.SecretReferenceName, false) {
			allErrs = append(allErrs, field.Invalid(tlsFld.Child("secretReferenceName"), httpCfg.TLS.SecretReferenceName, msg))
		}
	}

	return allErrs
}

func validateHTTPSURL(raw string, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	urlValue := strings.TrimSpace(raw)
	if urlValue == "" {
		allErrs = append(allErrs, field.Required(fldPath, "URL is required"))
	} else {
		// Validate URL format
		if outputURL, err := url.Parse(urlValue); err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath, urlValue, "invalid URL format"))
		} else {
			if outputURL.Scheme != "https" {
				allErrs = append(allErrs, field.Invalid(fldPath, urlValue, "URL scheme must be 'https'"))
			}

			if outputURL.RawQuery != "" {
				allErrs = append(allErrs, field.Invalid(fldPath, urlValue, "URL must not contain query parameters"))
			}

			if outputURL.Fragment != "" {
				allErrs = append(allErrs, field.Invalid(fldPath, urlValue, "URL must not contain fragments"))
			}

			if outputURL.User != nil {
				allErrs = append(allErrs, field.Invalid(fldPath, urlValue, "URL must not contain user information"))
			}
		}
	}

	return allErrs
}

const (
	clientCertKey = "client.crt"
	clientKeyKey  = "client.key"
	caCertKey     = "ca.crt"
)

// ValidateBackendHTTPTLSSecret validates that the referenced Secret contains the mandatory mTLS
// entries (client.crt, client.key) and optionally a CA bundle (ca.crt). All present entries must be non-empty.
// Errors are reported against fldPath (pointing to the referencing field) with secretReferenceName as value.
func ValidateBackendHTTPTLSSecret(secret *corev1.Secret, fldPath *field.Path, secretReferenceName string) field.ErrorList {
	var allErrs field.ErrorList

	if secret == nil {
		allErrs = append(allErrs, field.Invalid(fldPath, secretReferenceName, "referenced secret object is nil"))
		return allErrs
	}

	secretKey := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)

	checkKey := func(key string, required bool) {
		val, ok := secret.Data[key]
		if !ok {
			if required {
				allErrs = append(allErrs, field.Invalid(fldPath, secretReferenceName, fmt.Sprintf("missing %q data entry in referenced secret %q", key, secretKey)))
			}
			return
		}
		if len(bytes.TrimSpace(val)) == 0 {
			allErrs = append(allErrs, field.Invalid(fldPath, secretReferenceName, fmt.Sprintf("data entry %q in referenced secret %q is empty", key, secretKey)))
		}
	}

	checkKey(clientCertKey, true)
	checkKey(clientKeyKey, true)
	checkKey(caCertKey, false)

	// Stop if mandatory keys missing or empty.
	if len(allErrs) > 0 {
		return allErrs
	}

	var clientCert *x509.Certificate
	if certPEM, ok := secret.Data[clientCertKey]; ok {
		certs, err := parseCertificates(certPEM)
		switch {
		case err != nil:
			allErrs = append(allErrs, field.Invalid(fldPath, secretReferenceName, fmt.Sprintf("failed parsing %s: %v", clientCertKey, err)))
		case len(certs) == 0:
			allErrs = append(allErrs, field.Invalid(fldPath, secretReferenceName, fmt.Sprintf("no certificates found in %s", clientCertKey)))
		default:
			clientCert = certs[0]
		}
	}

	var privateKey any
	if keyPEM, ok := secret.Data[clientKeyKey]; ok {
		pk, err := parsePrivateKey(keyPEM)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath, secretReferenceName, fmt.Sprintf("failed parsing %s: %v", clientKeyKey, err)))
		} else {
			privateKey = pk
		}
	}

	if clientCert != nil && privateKey != nil {
		if !publicKeyMatches(privateKey, clientCert.PublicKey) {
			allErrs = append(allErrs, field.Invalid(fldPath, secretReferenceName, "client.key does not match client.crt public key"))
		}
	}

	if caPEM, ok := secret.Data[caCertKey]; ok && len(bytes.TrimSpace(caPEM)) > 0 {
		if _, err := parseCertificates(caPEM); err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath, secretReferenceName, fmt.Sprintf("failed parsing %s: %v", caCertKey, err)))
		}
	}

	return allErrs
}

// parseCertificates parses one or more PEM encoded certificates.
func parseCertificates(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificate PEM blocks found")
	}
	return certs, nil
}

// parsePrivateKey attempts to parse an RSA / ECDSA / Ed25519 or PKCS#8 private key from PEM.
func parsePrivateKey(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if pk, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return pk, nil
	}
	if pk, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return pk, nil
	}
	if pk, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return pk, nil
	}
	// Ed25519 keys are typically in PKCS#8, already handled; fallthrough error.
	return nil, fmt.Errorf("unknown or unsupported private key format")
}

// publicKeyMatches verifies that the private key corresponds to the provided public key.
func publicKeyMatches(privateKey any, publicKey any) bool {
	switch pk := privateKey.(type) {
	case *rsa.PrivateKey:
		pub, ok := publicKey.(*rsa.PublicKey)
		return ok && pk.N.Cmp(pub.N) == 0 && pk.E == pub.E
	case *ecdsa.PrivateKey:
		pub, ok := publicKey.(*ecdsa.PublicKey)
		return ok && pk.X.Cmp(pub.X) == 0 && pk.Y.Cmp(pub.Y) == 0
	case ed25519.PrivateKey:
		pub, ok := publicKey.(ed25519.PublicKey)
		return ok && bytes.Equal(pk.Public().(ed25519.PublicKey), pub)
	default:
		return false
	}
}
