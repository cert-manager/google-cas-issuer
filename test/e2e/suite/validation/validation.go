package validation

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
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
		casYAML := `apiVersion: cas-issuer.jetstack.io/v1
kind: GoogleCASIssuer
metadata:
  name: googlecasissuer-sample
  namespace: default
spec:
  project: project-name
  location: europe-west1
  caPoolId: some-pool
`
		dec := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
		apiObject := &unstructured.Unstructured{}
		_, gvk, err := dec.Decode([]byte(casYAML), nil, apiObject)
		Expect(err).NotTo(HaveOccurred())
		mapping, err := f.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		Expect(err).NotTo(HaveOccurred())

		dr := f.DynamicClientSet.Resource(mapping.Resource).Namespace(apiObject.GetNamespace())

		// Similar to `kubectl create`
		_, err = dr.Create(context.TODO(), apiObject, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Similar to `kubectl get`
		_, err = dr.Get(context.TODO(), apiObject.GetName(), metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Similar to `kubectl delete`
		err = dr.Delete(context.TODO(), apiObject.GetName(), metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})
})
