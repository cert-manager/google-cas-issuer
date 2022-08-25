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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="reason",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].reason"
// +kubebuilder:printcolumn:name="message",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].message"
// +kubebuilder:subresource:status
// GoogleCASClusterIssuer is the Schema for the googlecasclusterissuers API
type GoogleCASClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GoogleCASIssuerSpec   `json:"spec,omitempty"`
	Status GoogleCASIssuerStatus `json:"status,omitempty"`
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
