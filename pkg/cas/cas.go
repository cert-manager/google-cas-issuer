/*
Copyright 2020 the cert-manager authors.

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
	"fmt"
	"time"

	"cloud.google.com/go/security/privateca/apiv1beta1"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/google/uuid"
	"google.golang.org/api/option"
	casapi "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jetstack/google-cas-issuer/api/v1alpha1"
)

// A Signer is an abstraction of a certificate authority
type Signer interface {
	// Sign signs a CSR and returns a cert and chain
	Sign([]byte, time.Duration) ([]byte, []byte, error)
}

// A SignerBuilder constructs a Signer from an Issuer Spec
type SignerBuilder func(ctx context.Context, spec *v1alpha1.GoogleCASIssuerSpec, client client.Client) (Signer, error)

type casSigner struct {
	// parent is the Google cloud project ID in the format "projects/*/locations/*"
	parent string
	// certificateID is the root / subordinate CA to sign from
	certificateID string
	// spec is a reference to the issuer Spec
	spec *v1alpha1.GoogleCASIssuerSpec
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
	createCertificateRequest := &casapi.CreateCertificateRequest{
		Parent:        c.parent,
		CertificateId: c.certificateID,
		Certificate: &casapi.Certificate{
			CertificateConfig: &casapi.Certificate_PemCsr{
				PemCsr: string(csr),
			},
			Lifetime: &duration.Duration{
				Seconds: expiry.Milliseconds() / 1000,
				Nanos:   0,
			},
		},
		RequestId: uuid.New().String(),
	}
	createCertResp, err := casClient.CreateCertificate(c.ctx, createCertificateRequest)
	if err != nil {
		return nil, nil, err
	}

	certbuf := &bytes.Buffer{}
	certbuf.WriteString(createCertResp.PemCertificate)
	for _, c := range createCertResp.PemCertificateChain[:len(createCertResp.PemCertificateChain)-1] {
		certbuf.WriteString(c)
	}
	return certbuf.Bytes(), []byte(createCertResp.PemCertificateChain[len(createCertResp.PemCertificateChain)-1]), nil
}

func NewSigner(ctx context.Context, spec *v1alpha1.GoogleCASIssuerSpec, client client.Client, namespace string) (Signer, error) {
	c := &casSigner{
		parent:    fmt.Sprintf("projects/%s/locations/%s/certificateAuthorities/%s", spec.Project, spec.Location, spec.CertificateAuthorityID),
		spec:      spec,
		client:    client,
		ctx:       ctx,
		namespace: namespace,
	}
	if _, err := c.createCasClient(); err != nil {
		return nil, err
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
			return nil, fmt.Errorf("no credentials found at in secret %s under %s", secretNamespaceName, c.spec.Credentials.Key)
		}
		c, err := privateca.NewCertificateAuthorityClient(c.ctx, option.WithCredentialsJSON(credentials))
		if err != nil {
			return nil, err
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