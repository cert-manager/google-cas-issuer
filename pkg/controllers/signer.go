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
	"maps"
	"math/rand/v2"
	"slices"
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

// casClient defines the Google CAS client operations used during certificate signing,
// satisfied by *privateca.CertificateAuthorityClient.
type casClient interface {
	certificateCreator
	FetchCaCerts(ctx context.Context, req *casapi.FetchCaCertsRequest, opts ...gax.CallOption) (*casapi.FetchCaCertsResponse, error)
	Close() error
}

type GoogleCAS struct {
	client client.Client

	MaxRetryDuration time.Duration

	// newCasClient overrides createCasClient in unit tests when non-nil.
	newCasClient func(ctx context.Context, resourceNamespace string, issuerSpec *issuersv1beta1.GoogleCASIssuerSpec) (casClient, error)
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

// Sign implements signer.Sign for Google CAS.
func (o *GoogleCAS) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObj issuerapi.Issuer) (signer.PEMBundle, error) {
	issuerSpec, resourceNamespace := o.extractIssuerSpec(issuerObj)

	details, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, err
	}

	createClient := o.newCasClient
	if createClient == nil {
		createClient = func(ctx context.Context, resourceNamespace string, issuerSpec *issuersv1beta1.GoogleCASIssuerSpec) (casClient, error) {
			return o.createCasClient(ctx, resourceNamespace, issuerSpec)
		}
	}
	casClient, err := createClient(ctx, resourceNamespace, issuerSpec)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}
	defer casClient.Close()

	labels := buildCertificateLabels(cr, issuerSpec.CertificateMetadataPropagationMode)

	createCertResp, parent, err := createCertificateWithFallback(ctx, casClient, issuerSpec, details.CSR, details.Duration, labels)
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
	labels map[string]string,
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
			Labels:              labels,
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
	labels map[string]string,
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

		req, poolParent := buildCreateCertificateRequest(pool, issuerSpec.Project, csr, duration, labels)
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

// maxCertificateLabels is the maximum number of labels that Google Cloud allows on a resource.
const maxCertificateLabels = 64

// Keys of the provenance labels. They are valid GCP label keys as they are.
const (
	certificateNameLabelKey             = "cert-manager-io_certificate-name"
	certificateRequestNameLabelKey      = "cert-manager-io_certificate-request-name"
	certificateRequestNamespaceLabelKey = "cert-manager-io_certificate-request-namespace"
)

// buildCertificateLabels constructs a map of labels to be applied to a Google CAS Certificate,
// according to the CertificateMetadataPropagationMode of the issuer. It returns nil unless the
// issuer has opted in, so by default no labels are set.
// In "Provenance" mode it sets the provenance metadata: the name of the parent Certificate, and
// the name and namespace of the CertificateRequest.
// In "Labels" mode it additionally extracts native Kubernetes labels from the CertificateRequest
// (which natively inherits them from the parent Certificate), and applies GCP-compliant
// sanitization. To ensure idempotency and auditability, it injects provenance metadata first
// and then processes the remaining labels in a deterministic, alphabetically sorted order until
// the maxCertificateLabels limit is reached.
func buildCertificateLabels(cr signer.CertificateRequestObject, mode issuersv1beta1.CertificateMetadataPropagationMode) map[string]string {
	// Propagation is opt-in: no Kubernetes metadata leaves the cluster unless the issuer asks for it.
	if mode != issuersv1beta1.CertificateMetadataPropagationModeProvenance &&
		mode != issuersv1beta1.CertificateMetadataPropagationModeLabels {
		return nil
	}

	labels := make(map[string]string)

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
	if parentCertName := cr.GetAnnotations()[cmapi.CertificateNameKey]; parentCertName != "" {
		addLabel(certificateNameLabelKey, sanitizeGCPLabel(parentCertName, false))
	}
	if reqName := cr.GetName(); reqName != "" {
		addLabel(certificateRequestNameLabelKey, sanitizeGCPLabel(reqName, false))
	}
	// Kubernetes CertificateSigningRequests are cluster-scoped and have no namespace.
	if namespace := cr.GetNamespace(); namespace != "" {
		addLabel(certificateRequestNamespaceLabelKey, sanitizeGCPLabel(namespace, false))
	}

	if mode == issuersv1beta1.CertificateMetadataPropagationModeLabels {
		nativeLabels := cr.GetLabels()
		for _, k := range slices.Sorted(maps.Keys(nativeLabels)) {
			key := sanitizeGCPLabel(k, true)
			if hasReservedLabelKeyPrefix(key) {
				continue
			}
			addLabel(key, sanitizeGCPLabel(nativeLabels[k], false))
		}
	}

	if len(labels) == 0 {
		return nil
	}

	return labels
}

// reservedLabelKeyPrefixes are the label key prefixes reserved for the provenance labels.
var reservedLabelKeyPrefixes = []string{"cert-manager-io_", "cert-manager_io_", "cert_manager_io_"}

// hasReservedLabelKeyPrefix reports whether a sanitized label key starts with a prefix that is
// reserved for the provenance labels. Kubernetes labels with such keys are not propagated, so
// that they cannot pass for provenance labels, including the ones that are not set on a request.
func hasReservedLabelKeyPrefix(key string) bool {
	for _, prefix := range reservedLabelKeyPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// sanitizeGCPLabel ensures that a string conforms to the strict requirements for GCP labels.
// GCP Constraints for both Keys and Values:
// 1. Length must be at most 63 characters (after sanitization). Values can be empty, keys
// must be at least 1 character long.
// 2. Can only contain lowercase letters, numeric characters, underscores (_), and dashes (-).
//
// Additional Constraint for Keys (when isKey is true):
// 3. Must start with a lowercase letter.
//
// This function forces lowercase, replaces invalid characters with underscores, for keys
// prefixes with 'l-' if the first character is non-alphabetic, and truncates the result to
// 63 characters. An empty string is returned as is: an empty value is valid, and the caller
// skips empty keys.
func sanitizeGCPLabel(s string, isKey bool) string {
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	if isKey && (s[0] < 'a' || s[0] > 'z') {
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
