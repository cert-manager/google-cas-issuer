package issuer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	issuersv1alpha1 "github.com/jetstack/google-cas-issuer/api/v1alpha1"
)

func TestSetReadyCondition(t *testing.T) {
	tests := []struct {
		name                 string
		inputStatus          *issuersv1alpha1.GoogleCASIssuerStatus
		inputConditionStatus issuersv1alpha1.ConditionStatus
		inputReason          string
		inputMessage         string
		expectedStatus       *issuersv1alpha1.GoogleCASIssuerStatus
	}{
		{
			name:                 "Status with nil condition should be set",
			inputStatus:          &issuersv1alpha1.GoogleCASIssuerStatus{Conditions: nil},
			inputConditionStatus: issuersv1alpha1.ConditionTrue,
			inputReason:          "Test Ready Reason",
			inputMessage:         "Test Ready Message",
			expectedStatus: &issuersv1alpha1.GoogleCASIssuerStatus{
				Conditions: []issuersv1alpha1.GoogleCASIssuerCondition{},
			},
		},
	}
	for _, tt := range tests {
		status := tt.inputStatus.DeepCopy()
		setReadyCondition(status, tt.inputConditionStatus, tt.inputReason, tt.inputMessage)
		assert.Equal(t, status, tt.expectedStatus, "%s failed", tt.name)
	}
}
