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

package v1beta1

import (
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GoogleCASIssuerSpec defines the desired state of GoogleCASIssuer
type GoogleCASIssuerSpec struct {
	CAPool `json:",inline"`

	// Credentials is a reference to a Kubernetes Secret Key that contains Google Service Account Credentials
	// +optional
	Credentials cmmetav1.SecretKeySelector `json:"credentials,omitzero"`

	// Fallbacks is an ordered list of fallback CA pools to try if the primary pool fails.
	// The controller will attempt each fallback in order until one succeeds.
	// +optional
	Fallbacks []CAPool `json:"fallbacks,omitempty"`

	// CAFetchMode controls how the CA certificate chain is fetched and constructed.
	// Possible values: "CA" (default), "PoolCAs".
	// "CA": ca.crt contains root CA certificate of the Certificate Authority Service CA that has issued the certificate.
	// "PoolCAs": ca.crt contains all root CA certificates of all ENABLED, DISABLED, or STAGED Certificate Authority Service CA Pool CAs that are not expired.
	// +optional
	CAFetchMode CAFetchMode `json:"caFetchMode,omitempty"`
}

// CAPool defines a Google Cloud Certificate Authority Service CA pool configuration.
type CAPool struct {
	// Project is the Google Cloud Project ID for the CA pool.
	// Required on the primary spec; if omitted on a fallback pool, defaults to spec.project.
	// +optional
	// +kubebuilder:validation:MinLength=1
	Project string `json:"project,omitempty"`

	// Location is the Google Cloud Project Location of the CA pool.
	// +kubebuilder:validation:MinLength=1
	Location string `json:"location"`

	// CaPoolId is the ID of the CA pool to issue certificates from.
	// +kubebuilder:validation:MinLength=1
	CaPoolId string `json:"caPoolId"`

	// CertificateAuthorityId is a specific certificate authority to
	// use to sign. Omit in order to load balance across all CAs
	// in the pool.
	// +optional
	CertificateAuthorityId string `json:"certificateAuthorityId,omitempty"`

	// CertificateTemplate is a specific certificate template to
	// use. Omit to not specify a template.
	// +optional
	CertificateTemplate string `json:"certificateTemplate,omitempty"`
}

// +kubebuilder:validation:Enum=CA;PoolCAs
// CAFetchMode controls how the CA certificate chain is fetched and constructed.
type CAFetchMode string

const (
	// CAFetchModeCA indicates that only the issuing CA's root certificate should be fetched.
	CAFetchModeCA CAFetchMode = "CA"

	// CAFetchModePoolCAs indicates that all root certificates in the CA pool should be fetched.
	CAFetchModePoolCAs CAFetchMode = "PoolCAs"
)

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="reason",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].reason"
// +kubebuilder:printcolumn:name="message",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].message"
// +kubebuilder:subresource:status
// GoogleCASIssuer is the Schema for the googlecasissuers API
type GoogleCASIssuer struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata"`

	Spec GoogleCASIssuerSpec `json:"spec"`
	// +optional
	Status v1alpha1.IssuerStatus `json:"status,omitzero"`
}

func (vi *GoogleCASIssuer) GetConditions() []metav1.Condition {
	return vi.Status.Conditions
}

func (vi *GoogleCASIssuer) GetIssuerTypeIdentifier() string {
	return "googlecasissuers.cas-issuer.jetstack.io"
}

var _ v1alpha1.Issuer = &GoogleCASIssuer{}

// +kubebuilder:object:root=true
// GoogleCASIssuerList contains a list of GoogleCASIssuer
type GoogleCASIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata"`
	Items           []GoogleCASIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GoogleCASIssuer{}, &GoogleCASIssuerList{})
}
