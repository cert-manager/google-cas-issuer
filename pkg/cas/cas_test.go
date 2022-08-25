/*
Copyright 2021 Jetstack Ltd.

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

package cas

import (
	"context"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"

	"google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/jetstack/google-cas-issuer/api/v1"
)

func TestNewSigner(t *testing.T) {
	spec := &v1.GoogleCASIssuerSpec{
		CaPoolId: "test-pool",
		Project:  "test-project",
		Location: "test-location",
	}
	ctx := context.Background()
	namespace := "test"
	client := fake.NewFakeClient()
	res, err := newSignerNoSelftest(ctx, spec, client, namespace)
	if err != nil {
		t.Errorf("NewSigner returned an error: %s", err.Error())
	}
	if got, want := res.parent, fmt.Sprintf("projects/%s/locations/%s/caPools/%s", spec.Project, spec.Location, spec.CaPoolId); got != want {
		t.Errorf("Wrong parent: %s != %s", got, want)
	}
	if got, want := res.namespace, namespace; got != want {
		t.Errorf("Wrong namespace: %s != %s", got, want)
	}
}

func TestNewSignerMissingPoolId(t *testing.T) {
	spec := &v1.GoogleCASIssuerSpec{
		CaPoolId: "",
	}
	ctx := context.Background()
	namespace := "test"
	client := fake.NewFakeClient()
	_, err := newSignerNoSelftest(ctx, spec, client, namespace)
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
		input    *privateca.Certificate
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
			input: &privateca.Certificate{
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
			input: &privateca.Certificate{
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
