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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// GoogleCASClusterIssuerSpec defines the desired state of GoogleCASClusterIssuer
type GoogleCASClusterIssuerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Project is the Google Cloud Project ID
	Project string `json:"project,omitempty"`

	// Location is the Google Cloud Project Location
	Location string `json:"location,omitempty"`

	// CertificateAuthorityID is The ID of the Google Private certificate authority that will sign certificates
	CertificateAuthorityID string `json:"certificateAuthorityID,omitempty"`

	// Credentials is a reference to a Kubernetes Secret Key that contains Google Service Account Credentials
	// +optional
	Credentials NamespaceSecretKeySelector `json:"credentials,omitempty"`
}

// NamespaceSecretKeySelector contains the reference to a secret in a namespace.
type NamespaceSecretKeySelector struct {
	// The name of the secret in the given namespace to select from.
	Name string `json:"name,omitempty"`

	// The Namespace in which to get the secret
	Namespace string `json:"namespace,omitempty"`

	// The key of the secret to select from. Must be a valid secret key.
	Key string `json:"key,omitempty"`
}

// GoogleCASClusterIssuerStatus defines the observed state of GoogleCASClusterIssuer
type GoogleCASClusterIssuerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +optional
	Conditions []GoogleCASIssuerCondition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// GoogleCASClusterIssuer is the Schema for the googlecasclusterissuers API
type GoogleCASClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GoogleCASClusterIssuerSpec   `json:"spec,omitempty"`
	Status GoogleCASClusterIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GoogleCASClusterIssuerList contains a list of GoogleCASClusterIssuer
type GoogleCASClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GoogleCASClusterIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GoogleCASClusterIssuer{}, &GoogleCASClusterIssuerList{})
}
