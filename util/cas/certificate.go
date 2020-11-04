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

package cas

import (
	"context"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/google/uuid"
	casapi "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	"time"
)

// CreateCertificateOptions are options passed to CreateCertificate
type CreateCertificateOptions struct {
	// Parent is the Google cloud project ID in the format "projects/*/locations/*"
	Parent string
	// CertificateID is the root certificate ID to issue from
	CertificateID string
	// CSR is a PEM-encoded CSR
	CSR []byte
	// Expiry is the time from now to expire the certificate
	Expiry time.Duration
}

// CreateCertificate Signs a certificate
func (c *casClient) CreateCertificate(options *CreateCertificateOptions) (string, []string, error) {
	timeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	CreateCertificateRequest := &casapi.CreateCertificateRequest{
		Parent:        options.Parent,
		CertificateId: options.CertificateID,
		Certificate: &casapi.Certificate{
			CertificateConfig: &casapi.Certificate_PemCsr{
				PemCsr: string(options.CSR),
			},
			Lifetime: &duration.Duration{
				Seconds: options.Expiry.Milliseconds() / 1000,
				Nanos:   0,
			},
		},
		RequestId: uuid.New().String(),
	}
	createCertResp, err := c.client.CreateCertificate(timeout, CreateCertificateRequest)
	if err != nil {
		return "", nil, err
	}

	/* TODO: As per discussion in the cert-manager slack channel, cert-manager expects the
	 * intermediates to be inside the cert and the root to be in the CA; the opposite of what
	 * Google PrivateCA API returns.
	 */
	return createCertResp.PemCertificate, createCertResp.PemCertificateChain, nil
}
