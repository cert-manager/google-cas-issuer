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

// Package cas is a wrapper for the Google Cloud Private certificate authority service API
package cas

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/google/uuid"
	"google.golang.org/api/option"
	casapi "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jetstack/google-cas-issuer/api/v1beta1"
)

// A Signer is an abstraction of a certificate authority
type Signer interface {
	// Sign signs a CSR and returns a cert and chain
	Sign(csr []byte, expiry time.Duration) (cert []byte, ca []byte, err error)
}

type casSigner struct {
	// parent is the Google cloud project ID in the format "projects/*/locations/*"
	parent string
	// spec is a reference to the issuer Spec
	spec *v1beta1.GoogleCASIssuerSpec
	// namespace is the namespace to look for secrets in
	namespace string

	client client.Client
	ctx    context.Context
}

func (c *casSigner) Sign(csr []byte, expiry time.Duration) (cert []byte, ca []byte, err error) {
	casClient, err := c.createCasClient()
	if err != nil {
		return nil, nil, err
	}
	defer casClient.Close()
	createCertificateRequest := &casapi.CreateCertificateRequest{
		Parent: c.parent,
		// Should this use the certificate request name?
		CertificateId: fmt.Sprintf("cert-manager-%d", rand.Int()),
		Certificate: &casapi.Certificate{
			CertificateConfig: &casapi.Certificate_PemCsr{
				PemCsr: string(csr),
			},
			Lifetime: &duration.Duration{
				Seconds: expiry.Milliseconds() / 1000,
				Nanos:   0,
			},
			CertificateTemplate: c.spec.CertificateTemplate,
		},
		RequestId:                     uuid.New().String(),
		IssuingCertificateAuthorityId: c.spec.CertificateAuthorityId,
	}
	createCertResp, err := casClient.CreateCertificate(c.ctx, createCertificateRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("casClient.CreateCertificate failed: %w", err)
	}
	return extractCertAndCA(createCertResp)
}

func NewSigner(ctx context.Context, spec *v1beta1.GoogleCASIssuerSpec, client client.Client, namespace string) (Signer, error) {
	c, err := newSignerNoSelftest(ctx, spec, client, namespace)
	if err != nil {
		return c, err
	}
	casClient, err := c.createCasClient()
	if err != nil {
		return nil, err
	}
	casClient.Close()
	return c, nil
}

// newSignerNoSelftest creates a Signer without doing a self-check, useful for tests
func newSignerNoSelftest(ctx context.Context, spec *v1beta1.GoogleCASIssuerSpec, client client.Client, namespace string) (*casSigner, error) {
	if spec.CaPoolId == "" {
		return nil, fmt.Errorf("must specify a CaPoolId")
	}
	c := &casSigner{
		parent:    fmt.Sprintf("projects/%s/locations/%s/caPools/%s", spec.Project, spec.Location, spec.CaPoolId),
		spec:      spec,
		client:    client,
		ctx:       ctx,
		namespace: namespace,
	}
	return c, nil
}

func (c *casSigner) createCasClient() (*privateca.CertificateAuthorityClient, error) {
	var casClient *privateca.CertificateAuthorityClient

	if len(c.spec.Credentials.Name) > 0 && len(c.spec.Credentials.Key) > 0 {
		secretNamespaceName := types.NamespacedName{
			Name:      c.spec.Credentials.Name,
			Namespace: c.namespace,
		}
		var secret corev1.Secret
		if err := c.client.Get(c.ctx, secretNamespaceName, &secret); err != nil {
			return nil, err
		}
		credentials, exists := secret.Data[c.spec.Credentials.Key]
		if !exists {
			return nil, fmt.Errorf("no credentials found in secret %s under %s", secretNamespaceName, c.spec.Credentials.Key)
		}
		c, err := privateca.NewCertificateAuthorityClient(c.ctx, option.WithCredentialsJSON(credentials))
		if err != nil {
			return nil, fmt.Errorf("failed to build certificate authority client: %w", err)
		}
		casClient = c
	} else {
		// Using implicit credentials, e.g. with Google cloud service accounts
		c, err := privateca.NewCertificateAuthorityClient(c.ctx)
		if err != nil {
			return nil, err
		}
		casClient = c
	}
	return casClient, nil
}

// extractCertAndCA takes a response from the Google CAS API and formats it into a format
// expected by cert-manager. A Certificate contains the leaf in the PemCertificate field
// and the rest of the chain down to the root in the PemCertificateChain. cert-manager
// expects the leaf and all intermediates in the certificate field, stacked in PEM format
// with the root in the CA field.
//
// Additionally, for each PEM block, all whitespace is trimmed and a single new line is
// appended, in case software consuming the resulting secret writes the PEM blocks
// directly into a config file without parsing them.
func extractCertAndCA(resp *casapi.Certificate) (cert []byte, ca []byte, err error) {
	if resp == nil {
		return nil, nil, errors.New("extractCertAndCA: certificate response is nil")
	}
	certBuf := &bytes.Buffer{}

	// Write the leaf to the buffer
	certBuf.WriteString(strings.TrimSpace(resp.PemCertificate))
	certBuf.WriteRune('\n')

	// Write any remaining certificates except for the root-most one
	for _, c := range resp.PemCertificateChain[:len(resp.PemCertificateChain)-1] {
		certBuf.WriteString(strings.TrimSpace(c))
		certBuf.WriteRune('\n')
	}

	// Return the root-most certificate in the CA field.
	return certBuf.Bytes(), []byte(
		strings.TrimSpace(
			resp.PemCertificateChain[len(resp.PemCertificateChain)-1],
		) + "\n"), nil
}
