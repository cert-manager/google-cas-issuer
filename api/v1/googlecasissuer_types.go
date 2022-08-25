/*
Copyright 2021 Jetstack Ltd.

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

package v1

import (
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
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
	Credentials cmmetav1.SecretKeySelector `json:"credentials,omitempty"`
}

// GoogleCASIssuerStatus defines the observed state of GoogleCASIssuer
type GoogleCASIssuerStatus struct {
	// +optional
	Conditions []GoogleCASIssuerCondition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="reason",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].reason"
// +kubebuilder:printcolumn:name="message",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].message"
// +kubebuilder:subresource:status
// GoogleCASIssuer is the Schema for the googlecasissuers API
type GoogleCASIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GoogleCASIssuerSpec   `json:"spec,omitempty"`
	Status GoogleCASIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// GoogleCASIssuerList contains a list of GoogleCASIssuer
type GoogleCASIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GoogleCASIssuer `json:"items"`
}

// +kubebuilder:validation:Enum=Ready
type GoogleCASIssuerConditionType string

const (
	// IssuerConditionReady indicates that a CAS Issuer is ready for use.
	// This is defined as:
	IssuerConditionReady GoogleCASIssuerConditionType = "Ready"
)

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

// IssuerCondition contains condition information for a CAS Issuer.
type GoogleCASIssuerCondition struct {
	// Type of the condition, currently ('Ready').
	Type GoogleCASIssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	// +kubebuilder:validation:Enum=True;False;Unknown
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

func init() {
	SchemeBuilder.Register(&GoogleCASIssuer{}, &GoogleCASIssuerList{})
}
