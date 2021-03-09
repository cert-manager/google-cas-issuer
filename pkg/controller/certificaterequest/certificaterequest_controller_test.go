package certificaterequest

import (
	"testing"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSanitiseCertificateRequest(t *testing.T) {
	tests := []struct {
		name          string
		inputSpec     *cmapi.CertificateRequestSpec
		expectedSpec  *cmapi.CertificateRequestSpec
		expectedError error
	}{
		{
			name: "nil duration should be replaced with default duration",
			inputSpec: &cmapi.CertificateRequestSpec{
				Duration:  nil,
				IssuerRef: cmmeta.ObjectReference{},
				Request:   []byte("invalid"),
				IsCA:      false,
				Usages:    nil,
			},
			expectedSpec: &cmapi.CertificateRequestSpec{
				Duration:  &metav1.Duration{Duration: cmapi.DefaultCertificateDuration},
				IssuerRef: cmmeta.ObjectReference{},
				Request:   []byte("invalid"),
				IsCA:      false,
				Usages:    nil,
			},
			expectedError: nil,
		},
		{
			name: "very short duration should be replaced with minimum default duration",
			inputSpec: &cmapi.CertificateRequestSpec{
				Duration:  &metav1.Duration{Duration: time.Minute},
				IssuerRef: cmmeta.ObjectReference{},
				Request:   []byte("invalid"),
				IsCA:      false,
				Usages:    nil,
			},
			expectedSpec: &cmapi.CertificateRequestSpec{
				Duration:  &metav1.Duration{Duration: cmapi.MinimumCertificateDuration},
				IssuerRef: cmmeta.ObjectReference{},
				Request:   []byte("invalid"),
				IsCA:      false,
				Usages:    nil,
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		err := sanitiseCertificateRequestSpec(tt.inputSpec)
		assert.Equal(t, tt.expectedSpec, tt.inputSpec, "%s failed", tt.name)
		assert.Equal(t, tt.expectedError, err, "%s failed", tt.name)
	}
}
