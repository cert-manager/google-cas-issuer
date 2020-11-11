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
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
	casapi "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
)

// CreateCAOptions are options for CreateCA
type CreateCAOptions struct {
	// CertificateAuthorityID is the unique ID for the certificate authority
	CertificateAuthorityID string
	// Subject is the certificate subject
	Subject *casapi.Subject
	// SubjectAltNames is the certificate subject alt names block
	SubjectAltNames *casapi.SubjectAltNames
	// Expiry is the time from now when the certificate expires
	Expiry time.Duration
	// Parent is the Google cloud project ID in the format "projects/*/locations/*"
	Parent string

	// Keyring is the Google Cloud KMS Keyring name
	Keyring string
	// Key is the Google Cloud KMS Key name
	Key string
	// KeyVersion is the Google Cloud KMS Key Version
	KeyVersion string
}

var CaAlreadyExistsError = errors.New("A CA with that name already exists")

// CreateCA creates a new certificate authority
func (c *casClient) CreateCA(options *CreateCAOptions) error {
	// TODO: should the timeout be configurable?
	timeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	createCAReq := &casapi.CreateCertificateAuthorityRequest{
		Parent:                 options.Parent,
		CertificateAuthorityId: options.CertificateAuthorityID,
		CertificateAuthority: &casapi.CertificateAuthority{
			Name: fmt.Sprintf("%s/certificateAuthorities/%s", options.Parent, options.CertificateAuthorityID),
			Type: casapi.CertificateAuthority_SELF_SIGNED,
			Tier: casapi.CertificateAuthority_ENTERPRISE,
			Config: &casapi.CertificateConfig{
				SubjectConfig: &casapi.CertificateConfig_SubjectConfig{
					Subject:        options.Subject,
					CommonName:     options.CertificateAuthorityID,
					SubjectAltName: options.SubjectAltNames,
				},
				ReusableConfig: &casapi.ReusableConfigWrapper{
					ConfigValues: &casapi.ReusableConfigWrapper_ReusableConfigValues{
						ReusableConfigValues: &casapi.ReusableConfigValues{
							KeyUsage: &casapi.KeyUsage{
								BaseKeyUsage: &casapi.KeyUsage_KeyUsageOptions{
									DigitalSignature: true,
									CertSign:         true,
									CrlSign:          true,
								},
								ExtendedKeyUsage:         nil,
								UnknownExtendedKeyUsages: nil,
							},
							CaOptions: &casapi.ReusableConfigValues_CaOptions{
								IsCa:                &wrappers.BoolValue{Value: true},
								MaxIssuerPathLength: &wrappers.Int32Value{Value: 2},
							},
							PolicyIds:            nil,
							AiaOcspServers:       nil,
							AdditionalExtensions: nil,
						},
					},
				},
			},
			Lifetime: &duration.Duration{
				Seconds: options.Expiry.Milliseconds() / 1000, // 1 year
				Nanos:   0,
			},
			KeySpec: &casapi.CertificateAuthority_KeyVersionSpec{
				KeyVersion: &casapi.CertificateAuthority_KeyVersionSpec_CloudKmsKeyVersion{
					//CloudKmsKeyVersion: fmt.Sprintf("%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", options.Parent, options.Keyring, options.Key, options.KeyVersion)
					CloudKmsKeyVersion: "projects/jetstack-cas/locations/europe-west1/keyRings/kr1/cryptoKeys/k1/cryptoKeyVersions/1",
				},
			},
		},
		RequestId: uuid.New().String(),
	}
	operation, err := c.client.CreateCertificateAuthority(timeout, createCAReq)
	if err != nil {
		return err
	}
	_, err = operation.Wait(timeout)
	if err != nil {
		return err
	}
	return nil
}

// ListCAOptions are options passed to ListCA
type ListCAOptions struct {
	// Parent is the Google cloud project ID in the format "projects/*/locations/*"
	Parent string
}

// ListCA returns a list of all certificate authorities we have access to
func (c *casClient) ListCA(options *ListCAOptions) ([]string, error) {
	// TODO: should the timeout be configurable?
	timeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	listCAReq := &casapi.ListCertificateAuthoritiesRequest{
		Parent: options.Parent,
	}
	CAs := c.client.ListCertificateAuthorities(timeout, listCAReq)
	var CAIDs []string
	for {
		item, err := CAs.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		CAIDs = append(CAIDs, item.Name)
	}
	return CAIDs, nil
}
