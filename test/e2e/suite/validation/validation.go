package validation

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"

	"github.com/jetstack/google-cas-issuer/test/e2e/framework"
)

var _ = framework.CasesDescribe("validation", func() {
	f := framework.NewDefaultFramework("validation")
	It("Has valid kubeconfig", func() {
		By("using the provided kubeconfig to list namespaces")
		_, err := f.KubeClientSet.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("Has cert-manager CRDs installed", func() {
		By("using the provided CM clientset to get clusterIssuers")
		_, err := f.CMClientSet.CertmanagerV1().ClusterIssuers().List(context.TODO(), metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("Has the google-cas-issuer CRDs installed", func() {
		By("using the dynamic client to create a google-cas-issuer")
		casYAML := `apiVersion: cas-issuer.jetstack.io/v1alpha1
kind: GoogleCASIssuer
metadata:
 name: googlecasissuer-sample
spec:
  project: project-name
  location: europe-west1
  certificateAuthorityID: my-sub-ca
`
		decoder := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
		_, err := f.CMClientSet.CertmanagerV1().ClusterIssuers().List(context.TODO(), metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
	})
})
