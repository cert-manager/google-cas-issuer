/*
Copyright 2024 The cert-manager Authors.

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
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	controllers "github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"google.golang.org/api/option"
	casapi "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	issuersv1beta1 "github.com/jetstack/google-cas-issuer/api/v1beta1"
)

var PickedupRequestConditionType = cmapi.CertificateRequestConditionType("pickedup")

type GoogleCAS struct {
	client client.Client

	MaxRetryDuration time.Duration
}

func (s *GoogleCAS) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	const fieldOwner = "cas-issuer.jetstack.io"

	if err := cmapi.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}

	if err := issuersv1beta1.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}

	s.client = mgr.GetClient()

	return (&controllers.CombinedController{
		IssuerTypes:        []issuerapi.Issuer{&issuersv1beta1.GoogleCASIssuer{}},
		ClusterIssuerTypes: []issuerapi.Issuer{&issuersv1beta1.GoogleCASClusterIssuer{}},

		FieldOwner:       fieldOwner,
		MaxRetryDuration: s.MaxRetryDuration,

		Sign:  s.Sign,
		Check: s.Check,

		SetCAOnCertificateRequest: true,

		EventRecorder: mgr.GetEventRecorderFor(fieldOwner),
	}).SetupWithManager(ctx, mgr)
}

func (o *GoogleCAS) extractIssuerSpec(obj client.Object) (issuerSpec *issuersv1beta1.GoogleCASIssuerSpec, namespace string) {
	switch t := obj.(type) {
	case *issuersv1beta1.GoogleCASIssuer:
		return &t.Spec, t.Namespace
	case *issuersv1beta1.GoogleCASClusterIssuer:
		return &t.Spec, viper.GetString("cluster-resource-namespace")
	}

	panic("Program Error: Unhandled issuer type")
}

func (o *GoogleCAS) Check(ctx context.Context, issuerObj issuerapi.Issuer) error {
	issuerSpec, resourceNamespace := o.extractIssuerSpec(issuerObj)

	casClient, _, err := o.createCasClient(ctx, resourceNamespace, issuerSpec)
	if err != nil {
		return err
	}
	casClient.Close()

	return nil
}

// Sign implements signer.Sign for Venafi TPP and Venafi-as-a-Service.
func (o *GoogleCAS) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObj issuerapi.Issuer) (signer.PEMBundle, error) {
	issuerSpec, resourceNamespace := o.extractIssuerSpec(issuerObj)

	_, duration, csrBlob, err := cr.GetRequest()
	if err != nil {
		return signer.PEMBundle{}, err
	}

	casClient, parent, err := o.createCasClient(ctx, resourceNamespace, issuerSpec)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}
	defer casClient.Close()

	createCertificateRequest := &casapi.CreateCertificateRequest{
		Parent: parent,
		// Should this use the certificate request name?
		CertificateId: fmt.Sprintf("cert-manager-%d", rand.Int()),
		Certificate: &casapi.Certificate{
			CertificateConfig: &casapi.Certificate_PemCsr{
				PemCsr: string(csrBlob),
			},
			Lifetime: &durationpb.Duration{
				Seconds: duration.Milliseconds() / 1000,
				Nanos:   0,
			},
			CertificateTemplate: issuerSpec.CertificateTemplate,
		},
		RequestId:                     uuid.New().String(),
		IssuingCertificateAuthorityId: issuerSpec.CertificateAuthorityId,
	}

	createCertResp, err := casClient.CreateCertificate(ctx, createCertificateRequest)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("casClient.CreateCertificate failed: %w", err)
	}

	chainPEM, caPem, err := extractCertAndCA(createCertResp)
	return signer.PEMBundle{
		ChainPEM: chainPEM,
		CAPEM:    caPem,
	}, err
}

func buildParentString(issuerSpec *issuersv1beta1.GoogleCASIssuerSpec) (string, error) {
	if issuerSpec.Project == "" {
		return "", signer.PermanentError{Err: fmt.Errorf("must specify a Project")}
	}
	if issuerSpec.Location == "" {
		return "", signer.PermanentError{Err: fmt.Errorf("must specify a Location")}
	}
	if issuerSpec.CaPoolId == "" {
		return "", signer.PermanentError{Err: fmt.Errorf("must specify a CaPoolId")}
	}

	parent := fmt.Sprintf("projects/%s/locations/%s/caPools/%s", issuerSpec.Project, issuerSpec.Location, issuerSpec.CaPoolId)

	return parent, nil
}

func (c *GoogleCAS) createCasClient(ctx context.Context, resourceNamespace string, issuerSpec *issuersv1beta1.GoogleCASIssuerSpec) (*privateca.CertificateAuthorityClient, string, error) {
	parent, err := buildParentString(issuerSpec)
	if err != nil {
		return nil, "", err
	}

	var casClient *privateca.CertificateAuthorityClient
	if len(issuerSpec.Credentials.Name) > 0 && len(issuerSpec.Credentials.Key) > 0 {
		secretNamespaceName := types.NamespacedName{
			Name:      issuerSpec.Credentials.Name,
			Namespace: resourceNamespace,
		}
		var secret corev1.Secret
		if err := c.client.Get(ctx, secretNamespaceName, &secret); err != nil {
			return nil, "", err
		}
		credentials, exists := secret.Data[issuerSpec.Credentials.Key]
		if !exists {
			return nil, "", fmt.Errorf("no credentials found in secret %s under %s", secretNamespaceName, issuerSpec.Credentials.Key)
		}
		c, err := privateca.NewCertificateAuthorityClient(ctx, option.WithCredentialsJSON(credentials))
		if err != nil {
			return nil, "", fmt.Errorf("failed to build certificate authority client: %w", err)
		}
		casClient = c
	} else {
		// Using implicit credentials, e.g. with Google cloud service accounts
		c, err := privateca.NewCertificateAuthorityClient(ctx)
		if err != nil {
			return nil, "", err
		}
		casClient = c
	}

	return casClient, parent, nil
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
