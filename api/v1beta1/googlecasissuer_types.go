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
	// Project is the Google Cloud Project ID
	Project string `json:"project,omitempty"`

	// Location is the Google Cloud Project Location
	Location string `json:"location,omitempty"`

	// CaPoolId is the id of the CA pool to issue certificates from
	CaPoolId string `json:"caPoolId,omitempty"`

	// CertificateAuthorityId is specific certificate authority to
	// use to sign. Omit in order to load balance across all CAs
	// in the pool
	// +optional
	CertificateAuthorityId string `json:"certificateAuthorityId,omitempty"`

	// Credentials is a reference to a Kubernetes Secret Key that contains Google Service Account Credentials
	// +optional
	Credentials cmmetav1.SecretKeySelector `json:"credentials,omitzero"`

	// CertificateTemplate is specific certificate template to
	// use. Omit to not specify a template
	// +optional
	CertificateTemplate string `json:"certificateTemplate,omitempty"`
}

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
