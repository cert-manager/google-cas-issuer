package issuer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	issuersv1 "github.com/jetstack/google-cas-issuer/api/v1"
)

func TestSetReadyCondition(t *testing.T) {
	tests := []struct {
		name                 string
		inputStatus          *issuersv1.GoogleCASIssuerStatus
		inputConditionStatus issuersv1.ConditionStatus
		inputReason          string
		inputMessage         string
		expectedStatus       *issuersv1.GoogleCASIssuerStatus
	}{
		{
			name:                 "Status with nil condition should be set",
			inputStatus:          &issuersv1.GoogleCASIssuerStatus{Conditions: nil},
			inputConditionStatus: issuersv1.ConditionTrue,
			inputReason:          "Test Ready Reason",
			inputMessage:         "Test Ready Message",
			expectedStatus: &issuersv1.GoogleCASIssuerStatus{
				Conditions: []issuersv1.GoogleCASIssuerCondition{{
					Type:               issuersv1.IssuerConditionReady,
					Status:             issuersv1.ConditionTrue,
					LastTransitionTime: nil,
					Reason:             "Test Ready Reason",
					Message:            "Test Ready Message",
				}},
			},
		},
		{
			name: "Status can transition from Ready to Not Ready",
			inputStatus: &issuersv1.GoogleCASIssuerStatus{
				Conditions: []issuersv1.GoogleCASIssuerCondition{
					{
						Type:               issuersv1.IssuerConditionReady,
						Status:             issuersv1.ConditionTrue,
						LastTransitionTime: nil,
						Reason:             "I was Ready before",
						Message:            "Test Ready Message",
					},
				},
			},
			inputConditionStatus: issuersv1.ConditionFalse,
			inputReason:          "I'm not ready now reason",
			inputMessage:         "I'm not ready now message",
			expectedStatus: &issuersv1.GoogleCASIssuerStatus{
				Conditions: []issuersv1.GoogleCASIssuerCondition{{
					Type:               issuersv1.IssuerConditionReady,
					Status:             issuersv1.ConditionFalse,
					LastTransitionTime: nil,
					Reason:             "I'm not ready now reason",
					Message:            "I'm not ready now message",
				}},
			},
		},
		{
			name: "Status can transition from Not Ready to Ready",
			inputStatus: &issuersv1.GoogleCASIssuerStatus{
				Conditions: []issuersv1.GoogleCASIssuerCondition{
					{
						Type:               issuersv1.IssuerConditionReady,
						Status:             issuersv1.ConditionFalse,
						LastTransitionTime: nil,
						Reason:             "I was not ready before",
						Message:            "Test Ready Message",
					},
				},
			},
			inputConditionStatus: issuersv1.ConditionTrue,
			inputReason:          "I'm ready now reason",
			inputMessage:         "I'm ready now message",
			expectedStatus: &issuersv1.GoogleCASIssuerStatus{
				Conditions: []issuersv1.GoogleCASIssuerCondition{{
					Type:               issuersv1.IssuerConditionReady,
					Status:             issuersv1.ConditionTrue,
					LastTransitionTime: nil,
					Reason:             "I'm ready now reason",
					Message:            "I'm ready now message",
				}},
			},
		},
	}
	for _, tt := range tests {
		status := tt.inputStatus.DeepCopy()
		setReadyCondition(status, tt.inputConditionStatus, tt.inputReason, tt.inputMessage)
		// ignore time.now
		for i := range status.Conditions {
			status.Conditions[i].LastTransitionTime = nil
		}
		assert.Equal(t, tt.expectedStatus, status, "%s failed", tt.name)
	}
}
