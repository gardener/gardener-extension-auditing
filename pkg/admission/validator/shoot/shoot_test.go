// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package audit_test

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

	gardencore "github.com/gardener/gardener/pkg/apis/core"
	gardencoreinstall "github.com/gardener/gardener/pkg/apis/core/install"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"

	validator "github.com/gardener/gardener-extension-auditing/pkg/admission/validator/shoot"
	"github.com/gardener/gardener-extension-auditing/pkg/apis/auditing"
	auditinginstall "github.com/gardener/gardener-extension-auditing/pkg/apis/auditing/install"
	"github.com/gardener/gardener-extension-auditing/pkg/constants"
)

var _ = Describe("Shoot Validator", func() {
	var (
		scheme     *runtime.Scheme
		dec        runtime.Decoder
		ctx        context.Context
		secretName string
		namespace  string
	)

	encode := func(obj runtime.Object) []byte {
		b, err := json.Marshal(obj)
		Expect(err).NotTo(HaveOccurred())
		return b
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

	buildInternalShoot := func() *gardencore.Shoot {
		shootV1 := &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "s1",
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
							Raw: encode(
								&auditing.AuditConfiguration{
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
								},
							),
						},
					},
				},
			},
		}

		internal := &gardencore.Shoot{}
		Expect(scheme.Convert(shootV1, internal, nil)).To(Succeed())
		return internal
	}

	BeforeEach(func() {
		ctx = context.Background()
		secretName = "audit-tls"
		namespace = "ns"
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		gardencoreinstall.Install(scheme)
		auditinginstall.Install(scheme)
		dec = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()
	})

	It("should ignore shoots without auditing extension", func() {
		shootObj := &gardencore.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "s1",
				Namespace: namespace,
			},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		v := validator.NewShootValidator(c, dec)
		Expect(v.Validate(ctx, shootObj, nil)).To(Succeed())
	})

	It("should error when providerConfig is nil", func() {
		shootObj := &gardencore.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "s1",
				Namespace: namespace,
			},
			Spec: gardencore.ShootSpec{
				Extensions: []gardencore.Extension{
					{Type: constants.ExtensionType},
				},
			},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		v := validator.NewShootValidator(c, dec)
		err := v.Validate(ctx, shootObj, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("providerConfig is required"))
	})

	It("should fail decoding invalid providerConfig", func() {
		shootObj := &gardencore.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "s1",
				Namespace: namespace,
			},
			Spec: gardencore.ShootSpec{
				Extensions: []gardencore.Extension{
					{
						Type: constants.ExtensionType,
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"foo":"bar"}`),
						},
					},
				},
			},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		v := validator.NewShootValidator(c, dec)
		err := v.Validate(ctx, shootObj, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to decode providerConfig"))
	})

	It("should succeed with valid config and referenced secret", func() {
		secret := newCertSecret(true)
		shootObj := buildInternalShoot()
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
		v := validator.NewShootValidator(c, dec)
		Expect(v.Validate(ctx, shootObj, nil)).To(Succeed())
	})

	It("should error when referenced secret is missing", func() {
		shootObj := buildInternalShoot()
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		v := validator.NewShootValidator(c, dec)
		err := v.Validate(ctx, shootObj, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to retrieve referenced secret"))
	})

	It("should surface validation errors of the secret (missing keys)", func() {
		badSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace}, Data: map[string][]byte{"client.crt": []byte("dummy")}}
		shootObj := buildInternalShoot()
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(badSecret).Build()
		v := validator.NewShootValidator(c, dec)
		err := v.Validate(ctx, shootObj, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("missing \"client.key\""))
	})

	It("should error when secret reference resolves to non-Secret resource kind", func() {
		shootObj := buildInternalShoot()
		shootObj.Spec.Resources = []gardencore.NamedResourceReference{{Name: "audit-ref", ResourceRef: autoscalingv1.CrossVersionObjectReference{Kind: "ConfigMap", Name: "foo"}}}
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		v := validator.NewShootValidator(c, dec)
		err := v.Validate(ctx, shootObj, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid referenced resource"))
	})
})
