package leaderelection

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jetstack/google-cas-issuer/test/e2e/framework"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/util/retry"
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
		By("Finding all cas issuer leader election config maps")
		findAllCASIssuerConfigMaps := func() ([]*corev1.ConfigMap, error) {
			configMapList, err := f.KubeClientSet.CoreV1().ConfigMaps("cert-manager").List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				return nil, fmt.Errorf("couldn't retrieve a list of config maps: %w", err)
			}
			var configMaps []*corev1.ConfigMap
			for _, cm := range configMapList.Items {
				if leaderAnnotationJSON, found := cm.Annotations["control-plane.alpha.kubernetes.io/leader"]; found {
					leaderInfo := new(leaderElectionAnnotation)
					if err := json.Unmarshal([]byte(leaderAnnotationJSON), leaderInfo); err != nil {
						return nil, err
					}
					if strings.HasPrefix(leaderInfo.HolderIdentity, "google-cas-issuer") {
						configMaps = append(configMaps, &cm)
					}
				}
			}
			return configMaps, nil
		}

		configMaps, err := findAllCASIssuerConfigMaps()
		Expect(err).NotTo(HaveOccurred())
		By("Expecting only one config map pointing to a google CAS issuer")
		Expect(configMaps).Should(HaveLen(1))

		By("Scaling google cas issuer to 3 replicas")
		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			deployment, err := f.KubeClientSet.AppsV1().Deployments("cert-manager").Get(context.TODO(), "google-cas-issuer", metav1.GetOptions{})
			if err != nil {
				return err
			}
			want3Replicas := int32(3)
			newDeployment := deployment.DeepCopy()
			newDeployment.Spec.Replicas = &want3Replicas
			_, err = f.KubeClientSet.AppsV1().Deployments("cert-manager").Update(context.TODO(), newDeployment, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for all pods to be ready")
		err = f.Helper().WaitForPodsReady(f.Config().Namespace, 10*time.Second)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring there is still a single config map")
		configMaps, err = findAllCASIssuerConfigMaps()
		Expect(err).NotTo(HaveOccurred())
		Expect(configMaps).Should(HaveLen(1))

		By("Scaling google cas issuer to 1 replicas")
		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			deployment, err := f.KubeClientSet.AppsV1().Deployments("cert-manager").Get(context.TODO(), "google-cas-issuer", metav1.GetOptions{})
			if err != nil {
				return err
			}
			newDeployment := deployment.DeepCopy()
			want1Replica := int32(1)
			newDeployment.Spec.Replicas = &want1Replica
			_, err = f.KubeClientSet.AppsV1().Deployments("cert-manager").Update(context.TODO(), newDeployment, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for all pods to be ready")
		err = f.Helper().WaitForPodsReady(f.Config().Namespace, 10*time.Second)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring there is still a single config map")
		configMaps, err = findAllCASIssuerConfigMaps()
		Expect(err).NotTo(HaveOccurred())
		Expect(configMaps).Should(HaveLen(1))
	})
})
