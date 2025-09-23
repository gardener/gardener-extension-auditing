// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secret_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gardencoreinstall "github.com/gardener/gardener/pkg/apis/core/install"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"

	validator "github.com/gardener/gardener-extension-auditing/pkg/admission/validator/secret"
	"github.com/gardener/gardener-extension-auditing/pkg/apis/auditing"
	auditinginstall "github.com/gardener/gardener-extension-auditing/pkg/apis/auditing/install"
	"github.com/gardener/gardener-extension-auditing/pkg/constants"
)

var _ = Describe("Secret Validator", func() {
	var (
		scheme *runtime.Scheme
		dec    runtime.Decoder
		ctx    context.Context
		shoot  *gardencorev1beta1.Shoot

		secretName = "audit-tls"
		namespace  = "ns"
	)

	encode := func(obj runtime.Object) []byte {
		data, err := json.Marshal(obj)
		Expect(err).ToNot(HaveOccurred())

		return data
	}

	newCertSecret := func(withKey bool) *corev1.Secret {
		data := map[string][]byte{}
		if withKey {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			tmpl := x509.Certificate{SerialNumber: big.NewInt(1)}
			der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
			Expect(err).NotTo(HaveOccurred())
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			keyBytes, err := x509.MarshalECPrivateKey(priv)
			Expect(err).NotTo(HaveOccurred())
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
			data["client.crt"] = certPEM
			data["client.key"] = keyPEM
		}
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace}, Data: data}
	}

	BeforeEach(func() {
		ctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		gardencoreinstall.Install(scheme)
		auditinginstall.Install(scheme)
		dec = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()

		shoot = &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shoot1",
				Namespace: namespace,
			},
			Spec: gardencorev1beta1.ShootSpec{
				Resources: []gardencorev1beta1.NamedResourceReference{
					{
						Name:        "audit-ref",
						ResourceRef: autoscalingv1.CrossVersionObjectReference{Kind: "Secret", Name: secretName},
					},
				},
				Extensions: []gardencorev1beta1.Extension{
					{
						Type: constants.ExtensionType,
						ProviderConfig: &runtime.RawExtension{
							Raw: encode(&auditing.AuditConfiguration{
								Backends: []auditing.AuditBackend{
									{
										HTTP: &auditing.BackendHTTP{
											URL: "https://example.com",
											TLS: auditing.TLSConfig{
												SecretReferenceName: "audit-ref",
											},
										},
									},
								},
							}),
						},
					},
				},
			},
		}
	})

	It("should ignore secret that is not referenced", func() {
		secret := newCertSecret(true)
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
		v := validator.NewSecretValidator(c, dec)
		Expect(v.Validate(ctx, secret, nil)).To(Succeed())
	})

	It("should succeed for referenced secret with valid data", func() {
		secret := newCertSecret(true)
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret, shoot).Build()
		v := validator.NewSecretValidator(c, dec)
		Expect(v.Validate(ctx, secret, nil)).To(Succeed())
	})

	It("should error for referenced secret missing mandatory keys", func() {
		secret := newCertSecret(false) // no keys
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret, shoot).Build()
		v := validator.NewSecretValidator(c, dec)
		err := v.Validate(ctx, secret, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("missing \"client.crt\""))
	})

	It("should return decoding error when shoot providerConfig is invalid", func() {
		secret := newCertSecret(true)
		shoot.Spec.Extensions = []gardencorev1beta1.Extension{{Type: constants.ExtensionType, ProviderConfig: &runtime.RawExtension{Raw: []byte(`{"foo":"bar"}`)}}}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret, shoot).Build()
		v := validator.NewSecretValidator(c, dec)
		err := v.Validate(ctx, secret, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(`failed to decode auditing providerConfig for shoot ns/shoot1: strict decoding error: unknown field "foo"`))
	})

	It("should ignore shoots where resource reference kind is not Secret", func() {
		secret := newCertSecret(true)
		shoot.Spec.Resources = []gardencorev1beta1.NamedResourceReference{{Name: "audit-ref", ResourceRef: autoscalingv1.CrossVersionObjectReference{Kind: "ConfigMap", Name: "cm"}}}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret, shoot).Build()
		v := validator.NewSecretValidator(c, dec)
		// reference resolution will fail and be skipped => success
		Expect(v.Validate(ctx, secret, nil)).To(Succeed())
	})
})
