package leaderelection

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/google-cas-issuer/test/e2e/framework"
)

type leaderElectionAnnotation struct {
	HolderIdentity       string    `json:"holderIdentity"`
	LeaseDurationSeconds int       `json:"leaseDurationSeconds"`
	AcquireTime          time.Time `json:"acquireTime"`
	RenewTime            time.Time `json:"renewTime"`
	LeaderTransitions    int       `json:"leaderTransitions"`
}

var _ = framework.CasesDescribe("leader election", func() {
	f := framework.NewDefaultFramework("leader election")
	It("Tests leader election", func() {
		By("Waiting for all pods to be ready")
		err := f.Helper().WaitForPodsReady(f.Config().Namespace, 10*time.Second)
		Expect(err).NotTo(HaveOccurred())
		_, err = f.KubeClientSet.CoordinationV1().Leases(f.Config().Namespace).Get(context.TODO(), "cm-google-cas-issuer", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})
})
