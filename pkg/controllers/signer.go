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
	"strings"
	"time"
	"unicode/utf8"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	casapi "cloud.google.com/go/security/privateca/apiv1/privatecapb"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	controllerslib "github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/google/uuid"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/spf13/viper"
	"google.golang.org/api/option"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	issuersv1beta1 "github.com/cert-manager/google-cas-issuer/api/v1beta1"
)

var PickedupRequestConditionType = cmapi.CertificateRequestConditionType("pickedup")

const (
	// maxFallbackErrorLen is the maximum byte length for the final formatted failover error,
	// keeping Kubernetes Event and Condition messages within the 1024-character limit
	// while leaving headroom for controller/issuer-lib prefixes.
	maxFallbackErrorLen = 900
	// maxPoolErrorLen bounds each individual pool's error description so a verbose error on one pool
	// cannot crowd out the remaining fallback pool paths and errors in the combined message.
	maxPoolErrorLen = 200
)

// certificateCreator defines the interface for creating certificates with Google CAS,
// satisfied by *privateca.CertificateAuthorityClient.
type certificateCreator interface {
	CreateCertificate(ctx context.Context, req *casapi.CreateCertificateRequest, opts ...gax.CallOption) (*casapi.Certificate, error)
}

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

	casClient, err := o.createCasClient(ctx, resourceNamespace, issuerSpec)
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

	casClient, err := o.createCasClient(ctx, resourceNamespace, issuerSpec)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}
	defer casClient.Close()

	createCertResp, parent, err := createCertificateWithFallback(ctx, casClient, issuerSpec, details.CSR, details.Duration)
	if err != nil {
		return signer.PEMBundle{}, err
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

func buildCreateCertificateRequest(
	pool issuersv1beta1.CAPool,
	defaultProject string,
	csr []byte,
	duration time.Duration,
) (*casapi.CreateCertificateRequest, string) {
	project := pool.Project
	if project == "" {
		project = defaultProject
	}
	parent := fmt.Sprintf("projects/%s/locations/%s/caPools/%s", project, pool.Location, pool.CaPoolId)

	req := &casapi.CreateCertificateRequest{
		Parent: parent,
		// Should this use the certificate request name?
		CertificateId: fmt.Sprintf("cert-manager-%d", rand.Int()),
		Certificate: &casapi.Certificate{
			CertificateConfig: &casapi.Certificate_PemCsr{
				PemCsr: string(csr),
			},
			Lifetime: &durationpb.Duration{
				Seconds: duration.Milliseconds() / 1000,
				Nanos:   0,
			},
			CertificateTemplate: pool.CertificateTemplate,
		},
		RequestId:                     uuid.New().String(),
		IssuingCertificateAuthorityId: pool.CertificateAuthorityId,
	}
	return req, parent
}

// createCertificateWithFallback attempts to create a certificate using the primary CA pool.
// If the primary attempt fails and fallback CA pools are configured, it retries each
// fallback in order. Returns the certificate response, the parent string of the pool that
// successfully signed (for use in subsequent FetchCaCerts calls), and any error.
func createCertificateWithFallback(
	ctx context.Context,
	casClient certificateCreator,
	issuerSpec *issuersv1beta1.GoogleCASIssuerSpec,
	csr []byte,
	duration time.Duration,
) (*casapi.Certificate, string, error) {
	log := ctrl.LoggerFrom(ctx)
	pools := append([]issuersv1beta1.CAPool{issuerSpec.CAPool}, issuerSpec.Fallbacks...)

	var primaryParent string
	var primaryErr error
	fbErrs := make([]string, 0, len(issuerSpec.Fallbacks))

	for i, pool := range pools {
		if i > 0 {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, "", fmt.Errorf("casClient.CreateCertificate failed: %w", ctxErr)
			}
		}

		req, poolParent := buildCreateCertificateRequest(pool, issuerSpec.Project, csr, duration)
		resp, err := casClient.CreateCertificate(ctx, req)
		if err == nil {
			if i > 0 {
				log.Info("Successfully issued certificate using fallback CA pool",
					"fallbackIndex", i-1,
					"fallbackPool", poolParent,
				)
			}
			return resp, poolParent, nil
		}

		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", fmt.Errorf("casClient.CreateCertificate failed: %w", ctxErr)
		}
		if len(issuerSpec.Fallbacks) == 0 {
			return nil, "", fmt.Errorf("casClient.CreateCertificate failed: %w", err)
		}

		if i == 0 {
			primaryParent = poolParent
			primaryErr = err
			log.Info("Primary CA pool signing failed; triggering failover to fallback pools",
				"primaryPool", poolParent,
				"error", err,
			)
		} else {
			log.Info("Fallback CA pool signing failed",
				"fallbackIndex", i-1,
				"fallbackPool", poolParent,
				"error", err,
			)
			fbErrs = append(fbErrs, fmt.Sprintf("fallback[%d] (%s: %s)", i-1, poolParent, cleanErrorMessage(err)))
		}
	}

	finalMsg := fmt.Sprintf("casClient.CreateCertificate failed on Primary (%s: %s); all %d fallback CA pools also failed: %s",
		primaryParent, cleanErrorMessage(primaryErr), len(issuerSpec.Fallbacks), strings.Join(fbErrs, "; "))

	return nil, "", errors.New(truncateString(finalMsg, maxFallbackErrorLen))
}

// cleanErrorMessage extracts a clean, human-readable error description from gRPC and standard errors,
// omitting verbose metadata (like google.rpc.ErrorInfo) and truncating to maxPoolErrorLen bytes
// so Kubernetes Event and Condition messages remain well within 1024 characters.
func cleanErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	if st, ok := status.FromError(err); ok {
		return truncateString(fmt.Sprintf("%s: %s", st.Code(), st.Message()), maxPoolErrorLen)
	}
	return truncateString(err.Error(), maxPoolErrorLen)
}

func truncateString(s string, maxLen int) string {
	const ellipsis = "..."
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= len(ellipsis) {
		return ellipsis[:maxLen]
	}
	target := maxLen - len(ellipsis)
	for target > 0 && !utf8.RuneStart(s[target]) {
		target--
	}
	return s[:target] + ellipsis
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

func (c *GoogleCAS) createCasClient(ctx context.Context, resourceNamespace string, issuerSpec *issuersv1beta1.GoogleCASIssuerSpec) (*privateca.CertificateAuthorityClient, error) {
	if _, err := buildParentString(issuerSpec); err != nil {
		return nil, err
	}

	var casClient *privateca.CertificateAuthorityClient
	if len(issuerSpec.Credentials.Name) > 0 && len(issuerSpec.Credentials.Key) > 0 {
		secretNamespaceName := types.NamespacedName{
			Name:      issuerSpec.Credentials.Name,
			Namespace: resourceNamespace,
		}
		var secret corev1.Secret
		if err := c.client.Get(ctx, secretNamespaceName, &secret); err != nil {
			return nil, err
		}
		credentials, exists := secret.Data[issuerSpec.Credentials.Key]
		if !exists {
			return nil, fmt.Errorf("no credentials found in secret %s under %s", secretNamespaceName, issuerSpec.Credentials.Key)
		}
		c, err := privateca.NewCertificateAuthorityClient(ctx, option.WithCredentialsJSON(credentials))
		if err != nil {
			return nil, fmt.Errorf("failed to build certificate authority client: %w", err)
		}
		casClient = c
	} else {
		// Using implicit credentials, e.g. with Google cloud service accounts
		c, err := privateca.NewCertificateAuthorityClient(ctx)
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
