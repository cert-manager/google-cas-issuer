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
	"context"
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
	gax "github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/cert-manager/google-cas-issuer/api/v1beta1"
)

func TestBuildParentString(t *testing.T) {
	spec := &v1beta1.GoogleCASIssuerSpec{
		CaPoolId: "test-pool",
		Project:  "test-project",
		Location: "test-location",
	}
	parent, err := buildParentString(spec.Project, spec.Location, spec.CaPoolId)
	if err != nil {
		t.Errorf("buildParentString returned an error: %s", err.Error())
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
	_, err := buildParentString(spec.Project, spec.Location, spec.CaPoolId)
	if err == nil {
		t.Error("buildParentString didn't return an error")
	}
	if got, want := err.Error(), "must specify a CaPoolId"; got != want {
		t.Errorf("Wrong error: %s != %s", got, want)
	}
}

func TestBuildFallbackParentString(t *testing.T) {
	tests := []struct {
		name        string
		fb          v1beta1.FallbackCAPool
		wantParent  string
		wantErr     bool
		errContains string
	}{
		{
			name: "all fields specified",
			fb: v1beta1.FallbackCAPool{
				Project:  "fallback-project",
				Location: "us-west1",
				CaPoolId: "fb-pool",
			},
			wantParent: "projects/fallback-project/locations/us-west1/caPools/fb-pool",
		},
		{
			name: "missing project",
			fb: v1beta1.FallbackCAPool{
				Location: "us-west1",
				CaPoolId: "fb-pool",
			},
			wantErr:     true,
			errContains: "must specify a Project",
		},
		{
			name: "missing location",
			fb: v1beta1.FallbackCAPool{
				Project:  "project",
				CaPoolId: "pool",
			},
			wantErr:     true,
			errContains: "must specify a Location",
		},
		{
			name: "missing CaPoolId",
			fb: v1beta1.FallbackCAPool{
				Project:  "project",
				Location: "location",
			},
			wantErr:     true,
			errContains: "must specify a CaPoolId",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildParentString(tt.fb.Project, tt.fb.Location, tt.fb.CaPoolId)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantParent, got)
			}
		})
	}
}

type fakeCertificateCreator struct {
	createCertificateFn func(ctx context.Context, req *casapi.CreateCertificateRequest, opts ...gax.CallOption) (*casapi.Certificate, error)
	calls               []*casapi.CreateCertificateRequest
}

func (f *fakeCertificateCreator) CreateCertificate(ctx context.Context, req *casapi.CreateCertificateRequest, opts ...gax.CallOption) (*casapi.Certificate, error) {
	f.calls = append(f.calls, proto.Clone(req).(*casapi.CreateCertificateRequest))
	if f.createCertificateFn != nil {
		return f.createCertificateFn(ctx, req, opts...)
	}
	return nil, errors.New("not implemented")
}

func TestCreateCertificateWithFallback(t *testing.T) {
	primaryParent := "projects/my-project/locations/us-central1/caPools/primary-pool"
	fb1Parent := "projects/my-project/locations/us-east1/caPools/fallback-pool-1"
	fb2Parent := "projects/backup-project/locations/europe-west1/caPools/fallback-pool-2"

	baseSpec := &v1beta1.GoogleCASIssuerSpec{
		Project:             "my-project",
		Location:            "us-central1",
		CaPoolId:            "primary-pool",
		CertificateTemplate: "primary-template",
		Fallbacks: []v1beta1.FallbackCAPool{
			{
				// Project omitted: should default to my-project
				Location:               "us-east1",
				CaPoolId:               "fallback-pool-1",
				CertificateTemplate:    "fb1-template",
				CertificateAuthorityId: "ca-1",
			},
			{
				Project:                "backup-project",
				Location:               "europe-west1",
				CaPoolId:               "fallback-pool-2",
				CertificateTemplate:    "fb2-template",
				CertificateAuthorityId: "ca-2",
			},
		},
	}

	makeReq := func() *casapi.CreateCertificateRequest {
		return &casapi.CreateCertificateRequest{
			Parent:        primaryParent,
			CertificateId: "orig-cert-id",
			Certificate: &casapi.Certificate{
				CertificateTemplate: "primary-template",
			},
			RequestId: "orig-req-id",
		}
	}

	t.Run("Primary succeeds (no fallbacks attempted)", func(t *testing.T) {
		expectedCert := &casapi.Certificate{Name: "primary-cert"}
		fake := &fakeCertificateCreator{
			createCertificateFn: func(ctx context.Context, req *casapi.CreateCertificateRequest, opts ...gax.CallOption) (*casapi.Certificate, error) {
				return expectedCert, nil
			},
		}

		req := makeReq()
		resp, parent, err := createCertificateWithFallback(context.Background(), fake, req, primaryParent, baseSpec)

		require.NoError(t, err)
		assert.Equal(t, expectedCert, resp)
		assert.Equal(t, primaryParent, parent)
		require.Len(t, fake.calls, 1)
		assert.Equal(t, primaryParent, fake.calls[0].Parent)
	})

	t.Run("Primary fails, no fallbacks configured", func(t *testing.T) {
		specNoFallbacks := &v1beta1.GoogleCASIssuerSpec{
			Project:  "my-project",
			Location: "us-central1",
			CaPoolId: "primary-pool",
		}
		fake := &fakeCertificateCreator{
			createCertificateFn: func(ctx context.Context, req *casapi.CreateCertificateRequest, opts ...gax.CallOption) (*casapi.Certificate, error) {
				return nil, errors.New("primary unavailable")
			},
		}

		req := makeReq()
		resp, parent, err := createCertificateWithFallback(context.Background(), fake, req, primaryParent, specNoFallbacks)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "no fallbacks configured")
		assert.Nil(t, resp)
		assert.Empty(t, parent)
		require.Len(t, fake.calls, 1)
	})

	t.Run("Primary fails, 1st fallback fails, 2nd fallback succeeds", func(t *testing.T) {
		expectedCert := &casapi.Certificate{Name: "fallback-2-cert"}
		fake := &fakeCertificateCreator{
			createCertificateFn: func(ctx context.Context, req *casapi.CreateCertificateRequest, opts ...gax.CallOption) (*casapi.Certificate, error) {
				if req.Parent == primaryParent {
					return nil, errors.New("primary 503 unavailable")
				}
				if req.Parent == fb1Parent {
					return nil, errors.New("fb1 404 not found")
				}
				if req.Parent == fb2Parent {
					return expectedCert, nil
				}
				return nil, errors.New("unexpected parent")
			},
		}

		req := makeReq()
		resp, parent, err := createCertificateWithFallback(context.Background(), fake, req, primaryParent, baseSpec)

		require.NoError(t, err)
		assert.Equal(t, expectedCert, resp)
		assert.Equal(t, fb2Parent, parent)
		require.Len(t, fake.calls, 3)

		// Verify primary call
		assert.Equal(t, primaryParent, fake.calls[0].Parent)
		assert.Equal(t, "primary-template", fake.calls[0].Certificate.CertificateTemplate)

		// Verify 1st fallback: project inherited from primary spec, fields updated
		assert.Equal(t, fb1Parent, fake.calls[1].Parent)
		assert.Equal(t, "fb1-template", fake.calls[1].Certificate.CertificateTemplate)
		assert.Equal(t, "ca-1", fake.calls[1].IssuingCertificateAuthorityId)
		assert.NotEqual(t, "orig-req-id", fake.calls[1].RequestId)
		assert.NotEqual(t, "orig-cert-id", fake.calls[1].CertificateId)

		// Verify 2nd fallback: uses backup-project
		assert.Equal(t, fb2Parent, fake.calls[2].Parent)
		assert.Equal(t, "fb2-template", fake.calls[2].Certificate.CertificateTemplate)
		assert.Equal(t, "ca-2", fake.calls[2].IssuingCertificateAuthorityId)
		assert.NotEqual(t, fake.calls[1].RequestId, fake.calls[2].RequestId)
		assert.NotEqual(t, fake.calls[1].CertificateId, fake.calls[2].CertificateId)

		// Verify original caller's request was not mutated in place
		assert.Equal(t, primaryParent, req.Parent)
		assert.Equal(t, "orig-cert-id", req.CertificateId)
		assert.Equal(t, "orig-req-id", req.RequestId)
		assert.Equal(t, "primary-template", req.Certificate.CertificateTemplate)
	})

	t.Run("Primary and all fallbacks fail (bounded error format)", func(t *testing.T) {
		fake := &fakeCertificateCreator{
			createCertificateFn: func(ctx context.Context, req *casapi.CreateCertificateRequest, opts ...gax.CallOption) (*casapi.Certificate, error) {
				return nil, fmt.Errorf("error on %s", req.Parent)
			},
		}

		req := makeReq()
		resp, parent, err := createCertificateWithFallback(context.Background(), fake, req, primaryParent, baseSpec)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Empty(t, parent)
		assert.Contains(t, err.Error(), "casClient.CreateCertificate failed on Primary")
		assert.Contains(t, err.Error(), primaryParent)
		assert.Contains(t, err.Error(), "all 2 fallback CA pools also failed")
		assert.Contains(t, err.Error(), fb2Parent)
		assert.Less(t, len(err.Error()), 1024)
		require.Len(t, fake.calls, 3)
	})

	t.Run("Primary and single fallback fail", func(t *testing.T) {
		singleFallbackSpec := &v1beta1.GoogleCASIssuerSpec{
			Project:  "my-project",
			Location: "us-central1",
			CaPoolId: "primary-pool",
			Fallbacks: []v1beta1.FallbackCAPool{
				{
					Location: "us-west1",
					CaPoolId: "fallback-pool-1",
				},
			},
		}
		fake := &fakeCertificateCreator{
			createCertificateFn: func(ctx context.Context, req *casapi.CreateCertificateRequest, opts ...gax.CallOption) (*casapi.Certificate, error) {
				return nil, status.Error(codes.PermissionDenied, "permission denied")
			},
		}

		req := makeReq()
		resp, parent, err := createCertificateWithFallback(context.Background(), fake, req, primaryParent, singleFallbackSpec)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Empty(t, parent)
		assert.Contains(t, err.Error(), "failed on Primary")
		assert.Contains(t, err.Error(), "and fallback pool")
		assert.Contains(t, err.Error(), "PermissionDenied: permission denied")
		assert.Less(t, len(err.Error()), 1024)
		require.Len(t, fake.calls, 2)
	})

	t.Run("Context canceled during fallback iteration", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		fake := &fakeCertificateCreator{
			createCertificateFn: func(ctx context.Context, req *casapi.CreateCertificateRequest, opts ...gax.CallOption) (*casapi.Certificate, error) {
				if req.Parent == primaryParent {
					return nil, errors.New("primary unavailable")
				}
				if req.Parent == fb1Parent {
					// Cancel context after first fallback fails
					cancel()
					return nil, errors.New("fb1 unavailable")
				}
				return nil, errors.New("unexpected call")
			},
		}

		req := makeReq()
		resp, parent, err := createCertificateWithFallback(ctx, fake, req, primaryParent, baseSpec)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Empty(t, parent)
		assert.Contains(t, err.Error(), "context canceled before attempting fallback[1]")
		assert.Less(t, len(err.Error()), 1024)
		require.Len(t, fake.calls, 2)
	})

	t.Run("Context canceled: does not attempt fallbacks", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately

		fake := &fakeCertificateCreator{
			createCertificateFn: func(ctx context.Context, req *casapi.CreateCertificateRequest, opts ...gax.CallOption) (*casapi.Certificate, error) {
				return nil, ctx.Err()
			},
		}

		req := makeReq()
		resp, parent, err := createCertificateWithFallback(ctx, fake, req, primaryParent, baseSpec)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Empty(t, parent)
		assert.Equal(t, context.Canceled, err)
		require.Len(t, fake.calls, 1)
	})
}

func TestCleanErrorMessage(t *testing.T) {
	assert.Empty(t, cleanErrorMessage(nil))

	stdErr := errors.New("simple standard error")
	assert.Equal(t, "simple standard error", cleanErrorMessage(stdErr))

	grpcErr := status.Error(codes.Unavailable, "service temporarily unavailable")
	assert.Equal(t, "Unavailable: service temporarily unavailable", cleanErrorMessage(grpcErr))

	wrappedGrpcErr := fmt.Errorf("wrapped: %w", grpcErr)
	assert.Equal(t, "Unavailable: service temporarily unavailable", cleanErrorMessage(wrappedGrpcErr))
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
