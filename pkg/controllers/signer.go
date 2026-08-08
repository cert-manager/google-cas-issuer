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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	controllerslib "github.com/cert-manager/issuer-lib/controllers"
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
	"sigs.k8s.io/controller-runtime/pkg/controller"

	issuersv1beta1 "github.com/cert-manager/google-cas-issuer/api/v1beta1"
)

var PickedupRequestConditionType = cmapi.CertificateRequestConditionType("pickedup")

type GoogleCAS struct {
	client client.Client

	MaxRetryDuration time.Duration
}

// SetupWithManager sets up the controller with the provided controller options
func (s *GoogleCAS) SetupWithManager(ctx context.Context, mgr ctrl.Manager, ctrlOpts controller.Options) error {
	const fieldOwner = "cas-issuer.jetstack.io"

	if err := cmapi.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}

	if err := issuersv1beta1.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}

	s.client = mgr.GetClient()

	return (&controllerslib.CombinedController{
		IssuerTypes:        []issuerapi.Issuer{&issuersv1beta1.GoogleCASIssuer{}},
		ClusterIssuerTypes: []issuerapi.Issuer{&issuersv1beta1.GoogleCASClusterIssuer{}},

		FieldOwner:       fieldOwner,
		MaxRetryDuration: s.MaxRetryDuration,

		ControllerOptions: ctrlOpts,
		Sign:              s.Sign,
		Check:             s.Check,

		SetCAOnCertificateRequest: true,

		EventRecorder: mgr.GetEventRecorder(fieldOwner),
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

	details, err := cr.GetCertificateDetails()
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
				PemCsr: string(details.CSR),
			},
			Lifetime: &durationpb.Duration{
				Seconds: details.Duration.Milliseconds() / 1000,
				Nanos:   0,
			},
			CertificateTemplate: issuerSpec.CertificateTemplate,
			Labels:              o.buildCertificateLabels(cr),
		},
		RequestId:                     uuid.New().String(),
		IssuingCertificateAuthorityId: issuerSpec.CertificateAuthorityId,
	}

	createCertResp, err := casClient.CreateCertificate(ctx, createCertificateRequest)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("casClient.CreateCertificate failed: %w", err)
	}

	chainPEM, caPem, err := extractCertAndCA(createCertResp)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	if issuerSpec.CAFetchMode == issuersv1beta1.CAFetchModePoolCAs {
		// Fetch CA certs from the pool
		fetchCaCertsReq := &casapi.FetchCaCertsRequest{
			CaPool: parent,
		}
		fetchResp, err := casClient.FetchCaCerts(ctx, fetchCaCertsReq)
		if err != nil {
			return signer.PEMBundle{}, fmt.Errorf("casClient.FetchCaCerts failed: %w", err)
		}

		filteredCA, err := filterAndDeduplicateCAs(fetchResp.CaCerts)
		if err != nil {
			return signer.PEMBundle{}, fmt.Errorf("filterAndDeduplicateCAs failed: %w", err)
		}
		if len(filteredCA) > 0 {
			caPem = filteredCA
		}
	}

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

func filterAndDeduplicateCAs(caChains []*casapi.FetchCaCertsResponse_CertChain) ([]byte, error) {
	caBuf := &bytes.Buffer{}
	seen := make(map[string]struct{})
	now := time.Now()

	for _, chain := range caChains {
		for _, certPEM := range chain.Certificates {
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				return nil, fmt.Errorf("filterAndDeduplicateCAs: failed to decode PEM block")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("filterAndDeduplicateCAs: failed to parse certificate: %w", err)
			}

			if !cert.IsCA || !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				continue
			}

			if !cert.NotAfter.After(now) {
				continue
			}

			uniqueKey := string(cert.RawSubject) + string(cert.SubjectKeyId)
			if _, exists := seen[uniqueKey]; exists {
				continue
			}
			seen[uniqueKey] = struct{}{}

			caBuf.WriteString(strings.TrimSpace(certPEM))
			caBuf.WriteRune('\n')
		}
	}
	return caBuf.Bytes(), nil
}

const maxCertificateLabels = 60

// buildCertificateLabels constructs a map of labels to be applied to a Google CAS Certificate.
// It extracts native Kubernetes labels from the CertificateRequest (which natively inherits
// them from the parent Certificate), and applies GCP-compliant sanitization before returning
// the final map. To ensure idempotency and auditability, it injects provenance metadata first
// and then processes the remaining labels in a deterministic, alphabetically sorted order until
// the maxCertificateLabels limit is reached.
func (o *GoogleCAS) buildCertificateLabels(cr signer.CertificateRequestObject) map[string]string {
	labels := make(map[string]string)
	annotations := cr.GetAnnotations()
	nativeLabels := cr.GetLabels()

	addLabel := func(key, value string) {
		if key == "" || len(labels) >= maxCertificateLabels {
			return
		}
		if _, exists := labels[key]; exists {
			return
		}
		labels[key] = value
	}

	// Auto-inject provenance first so it is not dropped at the cap.
	if parentCertName := annotations["cert-manager.io/certificate-name"]; parentCertName != "" {
		addLabel(sanitizeGCPLabel("cert-manager-io_certificate-name", true), sanitizeGCPLabel(parentCertName, false))
	}
	addLabel(sanitizeGCPLabel("cert-manager-io_certificate-request-name", true), sanitizeGCPLabel(cr.GetName(), false))
	addLabel(sanitizeGCPLabel("cert-manager-io_certificate-request-namespace", true), sanitizeGCPLabel(cr.GetNamespace(), false))

	keys := make([]string, 0, len(nativeLabels))
	for k := range nativeLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		addLabel(sanitizeGCPLabel(k, true), sanitizeGCPLabel(nativeLabels[k], false))
	}

	return labels
}

// sanitizeGCPLabel ensures that a string conforms to the strict requirements for GCP labels.
// GCP Constraints for both Keys and Values:
// 1. Length must be between 1 and 63 characters (after sanitization).
// 2. Can only contain lowercase letters, numeric characters, underscores (_), and dashes (-).
//
// Additional Constraint for Keys (when isKey is true):
// 3. Must start with a lowercase letter.
//
// This function forces lowercase, replaces invalid characters with underscores, and
// for keys, prefixes with 'l-' if the first character is non-alphabetic.
func sanitizeGCPLabel(s string, isKey bool) string {
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	if isKey && (len(s) == 0 || s[0] < 'a' || s[0] > 'z') {
		s = "l-" + s
	}
	var sb strings.Builder
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			sb.WriteRune(ch)
		} else {
			sb.WriteRune('_')
		}
	}
	res := sb.String()
	if len(res) > 63 {
		return res[:63]
	}
	return res
}
