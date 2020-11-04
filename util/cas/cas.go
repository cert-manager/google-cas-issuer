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
	"cloud.google.com/go/security/privateca/apiv1beta1"
	"context"
	"google.golang.org/api/option"
)

// Client is an interface for the Certificate Authority Service
type Client interface {
	// CreateCA creates a new certificate authority
	CreateCA(options *CreateCAOptions) error
	// ListCA gets a list of CAs
	ListCA(options *ListCAOptions) ([]string, error)
	// CreateCertificate signs a new certificate
	CreateCertificate(options *CreateCertificateOptions) (cert string, chain []string, err error)
}

// casClient is a Client that talks to the Google Private CA API
type casClient struct {
	client *privateca.CertificateAuthorityClient
}

// New returns a CAS client
func New(opts ...option.ClientOption) (Client, error) {
	c, err := privateca.NewCertificateAuthorityClient(context.TODO(), opts...)
	if err != nil {
		return nil, err
	}
	return &casClient{client: c}, nil
}
