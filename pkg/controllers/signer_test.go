/*
Copyright 2021 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	casapi "cloud.google.com/go/security/privateca/apiv1/privatecapb"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/stretchr/testify/assert"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/google-cas-issuer/api/v1beta1"
)

func TestBuildParentString(t *testing.T) {
	spec := &v1beta1.GoogleCASIssuerSpec{
		CaPoolId: "test-pool",
		Project:  "test-project",
		Location: "test-location",
	}
	parent, err := buildParentString(spec)
	if err != nil {
		t.Errorf("NewSigner returned an error: %s", err.Error())
	}
	if got, want := parent, fmt.Sprintf("projects/%s/locations/%s/caPools/%s", spec.Project, spec.Location, spec.CaPoolId); got != want {
		t.Errorf("Wrong parent: %s != %s", got, want)
	}
}

func TestBuildParentStringMissingPoolId(t *testing.T) {
	spec := &v1beta1.GoogleCASIssuerSpec{
		Project:  "test-project",
		Location: "test-location",
		CaPoolId: "",
	}
	_, err := buildParentString(spec)
	if err == nil {
		t.Error("NewSigner didn't return an error")
	}
	if got, want := err.Error(), "must specify a CaPoolId"; got != want {
		t.Errorf("Wrong error: %s != %s", got, want)
	}
}

func TestExtractCertAndCA(t *testing.T) {
	type expected struct {
		cert []byte
		ca   []byte
		err  error
	}
	const rootCA = `-----BEGIN CERTIFICATE-----
MIICbjCCAhWgAwIBAgIRAIx1PjG13lEQB1ZqNm7c5sswCgYIKoZIzj0EAwIwgaEx
HjAcBgNVBAoTFW1rY2VydCBkZXZlbG9wbWVudCBDQTE7MDkGA1UECwwyamFrZXhr
c0AwMFdLU01BQzYyLjFwZXJjZW50Lm5ldHdvcmsgKEpha2UgU2FuZGVycykxQjBA
BgNVBAMMOW1rY2VydCBqYWtleGtzQDAwV0tTTUFDNjIuMXBlcmNlbnQubmV0d29y
ayAoSmFrZSBTYW5kZXJzKTAeFw0yMTA2MTQxMjU1NDNaFw0yMzA5MTQxMjU1NDNa
MGYxJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9wbWVudCBjZXJ0aWZpY2F0ZTE7MDkG
A1UECwwyamFrZXhrc0AwMFdLU01BQzYyLjFwZXJjZW50Lm5ldHdvcmsgKEpha2Ug
U2FuZGVycykwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARbbosQ+SfKKj3dalEF
J7/sESpINBiOVpwN+3AICP0oRnjX3fEWYvCTp7j4h3Hww4Tz1RNYCN8VsvV2BU9y
ndTIo2gwZjAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHwYD
VR0jBBgwFoAUbSUVuAPENX7tpcK0/pj0jqMHBxswHgYDVR0RBBcwFYITY2FzLWUy
ZS5qZXRzdGFjay5pbzAKBggqhkjOPQQDAgNHADBEAiBEzu5o0PIB9d5dAZJHF8re
/M30rr/PDo8eagMZBEfUuAIgI8OcOearnlofAz5AS94axOyIJXIH/H+4dNKCXkAV
V94=
-----END CERTIFICATE-----`

	testData := []struct {
		name     string
		input    *casapi.Certificate
		expected expected
	}{
		{
			name:  "nil input returns an error without panicking",
			input: nil,
			expected: expected{
				nil, nil, errors.New("extractCertAndCA: certificate response is nil"),
			},
		},
		{
			name: "cert signed directly by a CA returns single leaf, single root",
			input: &casapi.Certificate{
				PemCertificate: `-----BEGIN CERTIFICATE-----
MIIBtjCCAVwCCQDkGWfHQC96wTAJBgcqhkjOPQQBMGYxJzAlBgNVBAoTHm1rY2Vy
dCBkZXZlbG9wbWVudCBjZXJ0aWZpY2F0ZTE7MDkGA1UECwwyamFrZXhrc0AwMFdL
U01BQzYyLjFwZXJjZW50Lm5ldHdvcmsgKEpha2UgU2FuZGVycykwHhcNMjEwNjE0
MTMwMzU4WhcNMzEwNDIzMTMwMzU4WjBEMQswCQYDVQQGEwJHQjERMA8GA1UECgwI
SmV0c3RhY2sxIjAgBgNVBAMMGWxlYWYxLmNhcy1lMmUuamV0c3RhY2suaW8wdjAQ
BgcqhkjOPQIBBgUrgQQAIgNiAAQ3NFaJEUbrkM8+sVcbFUnzTttaOPo/deMcuMFB
kDRfJ7+G4H+VRMSm4oTXpUXSbr7cAppCvB+ePHh3qkIpeNq66oA2bUK4j8l78DPo
0H0S96Qz8bBHEBWtSAnCO7wymp4wCQYHKoZIzj0EAQNJADBGAiEA28LfGB4MQu1F
Db+mNOgU61RUz2JhH6b0MnL//0RYd/4CIQDAWWj5Mo0qSpUtcZ+yJKYnN4w+hKYo
z5B9C4cjanJ67w==
-----END CERTIFICATE-----`,
				PemCertificateChain: []string{rootCA},
			},
			expected: expected{
				[]byte(`-----BEGIN CERTIFICATE-----
MIIBtjCCAVwCCQDkGWfHQC96wTAJBgcqhkjOPQQBMGYxJzAlBgNVBAoTHm1rY2Vy
dCBkZXZlbG9wbWVudCBjZXJ0aWZpY2F0ZTE7MDkGA1UECwwyamFrZXhrc0AwMFdL
U01BQzYyLjFwZXJjZW50Lm5ldHdvcmsgKEpha2UgU2FuZGVycykwHhcNMjEwNjE0
MTMwMzU4WhcNMzEwNDIzMTMwMzU4WjBEMQswCQYDVQQGEwJHQjERMA8GA1UECgwI
SmV0c3RhY2sxIjAgBgNVBAMMGWxlYWYxLmNhcy1lMmUuamV0c3RhY2suaW8wdjAQ
BgcqhkjOPQIBBgUrgQQAIgNiAAQ3NFaJEUbrkM8+sVcbFUnzTttaOPo/deMcuMFB
kDRfJ7+G4H+VRMSm4oTXpUXSbr7cAppCvB+ePHh3qkIpeNq66oA2bUK4j8l78DPo
0H0S96Qz8bBHEBWtSAnCO7wymp4wCQYHKoZIzj0EAQNJADBGAiEA28LfGB4MQu1F
Db+mNOgU61RUz2JhH6b0MnL//0RYd/4CIQDAWWj5Mo0qSpUtcZ+yJKYnN4w+hKYo
z5B9C4cjanJ67w==
-----END CERTIFICATE-----
`), []byte(rootCA + "\n"), nil,
			},
		},
		{
			name: "the bottom most certificate ends up in the CA field (trivially)",
			input: &casapi.Certificate{
				PemCertificate: `-----BEGIN CERTIFICATE-----
leaf
-----END CERTIFICATE-----`,
				PemCertificateChain: []string{`-----BEGIN CERTIFICATE-----
intermediate2
-----END CERTIFICATE-----`, `-----BEGIN CERTIFICATE-----
intermediate1
-----END CERTIFICATE-----`, `-----BEGIN CERTIFICATE-----
root
-----END CERTIFICATE-----`},
			},
			expected: expected{
				[]byte(`-----BEGIN CERTIFICATE-----
leaf
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
intermediate2
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
intermediate1
-----END CERTIFICATE-----
`),
				[]byte(`-----BEGIN CERTIFICATE-----
root
-----END CERTIFICATE-----
`),
				nil,
			},
		},
	}

	for _, tt := range testData {
		cert, ca, err := extractCertAndCA(tt.input)
		assert.Equalf(t, tt.expected.cert, cert, "Test %s failed", tt.name)
		assert.Equalf(t, tt.expected.ca, ca, "Test %s failed", tt.name)
		assert.Equalf(t, tt.expected.err, err, "Test %s failed", tt.name)
	}
}

func TestFilterAndDeduplicateCAs(t *testing.T) {
	now := time.Now()
	validExpiry := now.Add(24 * time.Hour)
	expiredExpiry := now.Add(-24 * time.Hour)

	rootCA := generateTestCert(t, true, "root", "root", validExpiry, []byte("key1"))
	expiredRoot := generateTestCert(t, true, "expired", "expired", expiredExpiry, []byte("key2"))
	nonCA := generateTestCert(t, false, "leaf", "leaf", validExpiry, []byte("key3"))
	intermediate := generateTestCert(t, true, "inter", "root", validExpiry, []byte("key4"))
	duplicateRoot := generateTestCert(t, true, "root", "root", validExpiry, []byte("key1")) // Same Subject/SKI as rootCA
	differentRoot := generateTestCert(t, true, "root2", "root2", validExpiry, []byte("key5"))

	tests := []struct {
		name     string
		caChains []*casapi.FetchCaCertsResponse_CertChain
		want     []string // substrings we expect in output
		dontWant []string // substrings we expect NOT in output
	}{
		{
			name: "Valid Root CA",
			caChains: []*casapi.FetchCaCertsResponse_CertChain{
				{Certificates: []string{rootCA}},
			},
			want: []string{strings.TrimSpace(rootCA)},
		},
		{
			name: "Expired Root CA",
			caChains: []*casapi.FetchCaCertsResponse_CertChain{
				{Certificates: []string{expiredRoot}},
			},
			dontWant: []string{strings.TrimSpace(expiredRoot)},
		},
		{
			name: "Non-CA Certificate",
			caChains: []*casapi.FetchCaCertsResponse_CertChain{
				{Certificates: []string{nonCA}},
			},
			dontWant: []string{strings.TrimSpace(nonCA)},
		},
		{
			name: "Intermediate CA (Subject != Issuer)",
			caChains: []*casapi.FetchCaCertsResponse_CertChain{
				{Certificates: []string{intermediate}},
			},
			dontWant: []string{strings.TrimSpace(intermediate)},
		},
		{
			name: "Deduplication",
			caChains: []*casapi.FetchCaCertsResponse_CertChain{
				{Certificates: []string{rootCA, duplicateRoot}},
			},
			want: []string{strings.TrimSpace(rootCA)},
		},
		{
			name: "Multiple Valid Roots",
			caChains: []*casapi.FetchCaCertsResponse_CertChain{
				{Certificates: []string{rootCA, differentRoot}},
			},
			want: []string{strings.TrimSpace(rootCA), strings.TrimSpace(differentRoot)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes, err := filterAndDeduplicateCAs(tt.caChains)
			assert.NoError(t, err)
			got := string(gotBytes)

			for _, w := range tt.want {
				assert.Contains(t, got, w)
			}
			for _, dw := range tt.dontWant {
				assert.NotContains(t, got, dw)
			}

			if tt.name == "Deduplication" {
				assert.Contains(t, got, strings.TrimSpace(rootCA))
				assert.NotContains(t, got, strings.TrimSpace(duplicateRoot))
			}
		})
	}
}

func generateTestCert(t *testing.T, isCA bool, subject, issuer string, expiry time.Time, ski []byte) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	parentKey := key
	parentSubject := pkix.Name{CommonName: issuer}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              expiry,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
	}

	parent := &x509.Certificate{
		Subject: parentSubject,
	}

	var parentTmpl *x509.Certificate
	if subject == issuer {
		parentTmpl = template
	} else {
		parentTmpl = parent
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parentTmpl, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestSanitizeGCPLabel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		isKey    bool
		expected string
	}{
		{"Valid Label", "team-engineering", true, "team-engineering"},
		{"Uppercase to Lowercase", "Team-Engineering", true, "team-engineering"},
		{"Invalid Characters Replaced", "tenant/123@region", false, "tenant_123_region"},
		{"Key Starts with Number", "123-tenant", true, "l-123-tenant"},
		{"Key Starts with Alphabet", "a123-tenant", true, "a123-tenant"},
		{"Value Starts with Number", "123-tenant", false, "123-tenant"},
		{"Exceeds 63 characters", "this-is-a-very-long-label-that-is-way-longer-than-sixty-three-characters", true, "this-is-a-very-long-label-that-is-way-longer-than-sixty-three-c"},
		{"Key Starts with Number and Exceeds 63 characters once Prefixed", "1" + strings.Repeat("a", 62), true, "l-1" + strings.Repeat("a", 60)},
		{"Empty key", "", true, ""},
		{"Empty value", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeGCPLabel(tt.input, tt.isKey)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestBuildCertificateLabels(t *testing.T) {
	// A CertificateRequest as cert-manager creates it for a Certificate: the labels of
	// the Certificate are copied and the name of the Certificate is set as an annotation.
	labelledRequest := signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-request",
			Namespace: "default",
			Annotations: map[string]string{
				"cert-manager.io/certificate-name": "parent-cert",
				"some-other-annotation":            "ignored",
			},
			Labels: map[string]string{
				"team":         "platform",
				"Cost-Center!": "999",     // uppercase and exclamation
				"1st-region":   "us-east", // key starts with number
			},
		},
	})

	// A Kubernetes CertificateSigningRequest is cluster-scoped, so it has no namespace.
	clusterScopedRequest := signer.CertificateRequestObjectFromCertificateSigningRequest(&certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-csr",
		},
	})

	// A CertificateRequest that was not created for a Certificate and carries no metadata of its own.
	bareRequest := signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bare-request",
			Namespace: "default",
		},
	})

	// A CertificateRequest with a label that tries to pass for a provenance label.
	spoofingRequest := signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-request",
			Namespace: "default",
			Labels: map[string]string{
				"cert-manager-io_certificate-request-namespace": "another-namespace",
			},
		},
	})

	// A CertificateRequest that was not created for a Certificate, with a label that tries to
	// pass for the provenance label of a Certificate.
	spoofedCertificateNameRequest := signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bare-request",
			Namespace: "default",
			Labels: map[string]string{
				"cert-manager-io_certificate-name": "spoofed-cert",
			},
		},
	})

	// A Kubernetes CertificateSigningRequest, which has no namespace, with a label that tries to
	// pass for the namespace provenance label.
	spoofedNamespaceRequest := signer.CertificateRequestObjectFromCertificateSigningRequest(&certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-csr",
			Labels: map[string]string{
				"cert-manager-io_certificate-request-namespace": "kube-system",
			},
		},
	})

	// A CertificateRequest with two label keys that are identical once sanitized.
	collidingKeysRequest := signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-request",
			Namespace: "default",
			Labels: map[string]string{
				"Cost-Center": "uppercase-key",
				"cost-center": "lowercase-key",
			},
		},
	})

	// A CertificateRequest with two label keys that share a prefix longer than a GCP label key,
	// so that both are cut to the same 63 characters.
	longPrefixRequest := signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-request",
			Namespace: "default",
			Labels: map[string]string{
				"cost-attribution.platform-engineering.infrastructure.example.com/owner": "owner",
				"cost-attribution.platform-engineering.infrastructure.example.com/team":  "team",
			},
		},
	})

	// A CertificateRequest with a label that has an empty value.
	emptyValueRequest := signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-request",
			Namespace: "default",
			Labels: map[string]string{
				"environment.example.com/prod": "",
			},
		},
	})

	// A CertificateRequest with labels whose keys start with a reserved prefix once sanitized.
	reservedPrefixRequest := signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-request",
			Namespace: "default",
			Labels: map[string]string{
				"Cert-Manager-IO_owner":            "spoofed", // sanitized to cert-manager-io_owner
				"cert-manager.io/certificate-name": "spoofed", // sanitized to cert-manager_io_certificate-name
				"team":                             "platform",
			},
		},
	})

	tests := []struct {
		name string
		cr   signer.CertificateRequestObject
		mode v1beta1.CertificateMetadataPropagationMode
		want map[string]string
	}{
		{
			name: "nothing is propagated when the mode is not set",
			cr:   labelledRequest,
			mode: "",
			want: nil,
		},
		{
			name: "nothing is propagated in None mode",
			cr:   labelledRequest,
			mode: v1beta1.CertificateMetadataPropagationModeNone,
			want: nil,
		},
		{
			name: "nothing is propagated for an unknown mode",
			cr:   labelledRequest,
			mode: "Everything",
			want: nil,
		},
		{
			name: "Provenance mode propagates only the provenance labels",
			cr:   labelledRequest,
			mode: v1beta1.CertificateMetadataPropagationModeProvenance,
			want: map[string]string{
				"cert-manager-io_certificate-name":              "parent-cert",
				"cert-manager-io_certificate-request-name":      "test-request",
				"cert-manager-io_certificate-request-namespace": "default",
			},
		},
		{
			name: "a request without a namespace gets no namespace label",
			cr:   clusterScopedRequest,
			mode: v1beta1.CertificateMetadataPropagationModeProvenance,
			want: map[string]string{
				"cert-manager-io_certificate-request-name": "test-csr",
			},
		},
		{
			name: "Labels mode propagates provenance and sanitized Kubernetes labels",
			cr:   labelledRequest,
			mode: v1beta1.CertificateMetadataPropagationModeLabels,
			want: map[string]string{
				"cert-manager-io_certificate-name":              "parent-cert",
				"cert-manager-io_certificate-request-name":      "test-request",
				"cert-manager-io_certificate-request-namespace": "default",
				"team":         "platform",
				"cost-center_": "999",
				"l-1st-region": "us-east", // Key must be prepended with l-
			},
		},
		{
			name: "Labels mode without labels or annotations propagates the request provenance",
			cr:   bareRequest,
			mode: v1beta1.CertificateMetadataPropagationModeLabels,
			want: map[string]string{
				"cert-manager-io_certificate-request-name":      "bare-request",
				"cert-manager-io_certificate-request-namespace": "default",
			},
		},
		{
			name: "a Kubernetes label cannot override a provenance label",
			cr:   spoofingRequest,
			mode: v1beta1.CertificateMetadataPropagationModeLabels,
			want: map[string]string{
				"cert-manager-io_certificate-request-name":      "test-request",
				"cert-manager-io_certificate-request-namespace": "default",
			},
		},
		{
			name: "of two keys that are identical once sanitized, the first in alphabetical order is kept",
			cr:   collidingKeysRequest,
			mode: v1beta1.CertificateMetadataPropagationModeLabels,
			want: map[string]string{
				"cert-manager-io_certificate-request-name":      "test-request",
				"cert-manager-io_certificate-request-namespace": "default",
				"cost-center": "uppercase-key",
			},
		},
		{
			name: "keys with a long shared prefix are cut to the same 63 characters and the first is kept",
			cr:   longPrefixRequest,
			mode: v1beta1.CertificateMetadataPropagationModeLabels,
			want: map[string]string{
				"cert-manager-io_certificate-request-name":                        "test-request",
				"cert-manager-io_certificate-request-namespace":                   "default",
				"cost-attribution_platform-engineering_infrastructure_example_co": "owner",
			},
		},
		{
			name: "empty label values are kept",
			cr:   emptyValueRequest,
			mode: v1beta1.CertificateMetadataPropagationModeLabels,
			want: map[string]string{
				"cert-manager-io_certificate-request-name":      "test-request",
				"cert-manager-io_certificate-request-namespace": "default",
				"environment_example_com_prod":                  "",
			},
		},
		{
			name: "a request that was not created for a Certificate cannot pass for one",
			cr:   spoofedCertificateNameRequest,
			mode: v1beta1.CertificateMetadataPropagationModeLabels,
			want: map[string]string{
				"cert-manager-io_certificate-request-name":      "bare-request",
				"cert-manager-io_certificate-request-namespace": "default",
			},
		},
		{
			name: "a request without a namespace cannot pass for one",
			cr:   spoofedNamespaceRequest,
			mode: v1beta1.CertificateMetadataPropagationModeLabels,
			want: map[string]string{
				"cert-manager-io_certificate-request-name": "test-csr",
			},
		},
		{
			name: "Kubernetes labels with a reserved key prefix are not propagated",
			cr:   reservedPrefixRequest,
			mode: v1beta1.CertificateMetadataPropagationModeLabels,
			want: map[string]string{
				"cert-manager-io_certificate-request-name":      "test-request",
				"cert-manager-io_certificate-request-namespace": "default",
				"team": "platform",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCertificateLabels(tt.cr, tt.mode)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildCertificateLabelsLimit(t *testing.T) {
	bigLabels := make(map[string]string)
	for i := range 70 {
		bigLabels[fmt.Sprintf("key-%d", i)] = "val"
	}

	cr := signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "massive-label-request",
			Namespace: "default",
			Labels:    bigLabels,
		},
	})

	got := buildCertificateLabels(cr, v1beta1.CertificateMetadataPropagationModeLabels)
	assert.Len(t, got, 64) // the maximum number of labels on a Google Cloud resource

	// Provenance labels are added first, so they are never the ones that are dropped.
	assert.Equal(t, "massive-label-request", got["cert-manager-io_certificate-request-name"])
	assert.Equal(t, "default", got["cert-manager-io_certificate-request-namespace"])
}
