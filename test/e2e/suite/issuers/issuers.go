/*
Copyright 2024 The cert-manager Authors.

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

package issuers

import (
	"bytes"
	"context"
	"os"
	"text/template"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"

	"github.com/cert-manager/google-cas-issuer/test/e2e/framework"
	"github.com/cert-manager/google-cas-issuer/test/e2e/framework/config"
	"github.com/cert-manager/google-cas-issuer/test/e2e/util"

	_ "embed"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	issuerYAML string = `apiVersion: cas-issuer.jetstack.io/v1beta1
kind: GoogleCASIssuer
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
spec:
  project: {{ .Project }}
  location: {{ .Location }}
  caPoolId: {{ .Pool }}
  credentials:
    name: {{ .SecretName }}
    key: "{{ .SecretKey }}"
`

	issuerWithCAFetchModeYAML string = `apiVersion: cas-issuer.jetstack.io/v1beta1
kind: GoogleCASIssuer
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
spec:
  project: {{ .Project }}
  location: {{ .Location }}
  caPoolId: {{ .Pool }}
  credentials:
    name: {{ .SecretName }}
    key: "{{ .SecretKey }}"
  caFetchMode: {{ .CAFetchMode }}
`

	clusterIssuerYaml string = `apiVersion: cas-issuer.jetstack.io/v1beta1
kind: GoogleCASClusterIssuer
metadata:
  name: {{ .Name }}
spec:
  project: {{ .Project }}
  location: {{ .Location }}
  caPoolId: {{ .Pool }}
  credentials:
    name: {{ .SecretName }}
    key: "{{ .SecretKey }}"`

	issuerWithFallbackYAML string = `apiVersion: cas-issuer.jetstack.io/v1beta1
kind: GoogleCASIssuer
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
spec:
  project: {{ .Project }}
  location: {{ .Location }}
  caPoolId: {{ .Pool }}
  credentials:
    name: {{ .SecretName }}
    key: "{{ .SecretKey }}"
  fallbacks:
    - project: {{ .FallbackProject }}
      caPoolId: {{ .FallbackCaPoolId }}
      location: {{ .FallbackLocation }}
`
)

type templateConfig struct {
	Name             string
	Namespace        string
	Project          string
	Location         string
	Pool             string
	SecretName       string
	SecretKey        string
	CAFetchMode      string
	FallbackProject  string
	FallbackCaPoolId string
	FallbackLocation string
}

var _ = framework.CasesDescribe("issuers", func() {
	f := framework.NewDefaultFramework("issuer")
	cfg := config.GetConfig()

	createIssuerAndCertificate := func(t *templateConfig, yamlTemplate string, timeout time.Duration) string {
		secretNamespace := t.Namespace
		if secretNamespace == "" {
			secretNamespace = "cert-manager"
		}

		By("Creating Google Cloud Credentials Secret")
		data, err := os.ReadFile(os.Getenv("TEST_GOOGLE_APPLICATION_CREDENTIALS"))
		Expect(err).NotTo(HaveOccurred())
		secret, err := f.KubeClientSet.CoreV1().Secrets(secretNamespace).Create(
			context.TODO(),
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "google-credentials-",
					Namespace:    secretNamespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"google.json": data,
				},
			},
			metav1.CreateOptions{},
		)
		Expect(err).NotTo(HaveOccurred())

		t.SecretName = secret.Name
		t.SecretKey = "google.json"

		By("Constructing issuer from template")
		buf := &bytes.Buffer{}
		err = template.Must(template.New("issuer").Parse(yamlTemplate)).Execute(buf, t)
		Expect(err).NotTo(HaveOccurred())

		By("Creating dynamic object")
		dec := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
		apiObject := &unstructured.Unstructured{}
		_, gvk, err := dec.Decode(buf.Bytes(), nil, apiObject)
		Expect(err).NotTo(HaveOccurred())
		mapping, err := f.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		Expect(err).NotTo(HaveOccurred())

		dr := f.DynamicClientSet.Resource(mapping.Resource)

		if t.Namespace != "" {
			By("Creating issuer " + t.Namespace + "/" + t.Name)
			_, err = dr.Namespace(t.Namespace).Create(context.TODO(), apiObject, metav1.CreateOptions{})
		} else {
			By("Creating clusterissuer " + t.Name)
			_, err = dr.Create(context.TODO(), apiObject, metav1.CreateOptions{})
		}
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for issuer to become ready")
		err = f.Helper().WaitForUnstructuredReady(dr, t.Name, t.Namespace, timeout)
		Expect(err).NotTo(HaveOccurred())

		By("Creating a certificate")
		certName := "casissuer-e2e-" + util.RandomString(5)
		_, err = f.CMClientSet.CertmanagerV1().Certificates(cfg.Namespace).Create(context.TODO(), &certmanagerv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      certName,
				Namespace: cfg.Namespace,
			},
			Spec: certmanagerv1.CertificateSpec{
				SecretName:  certName,
				CommonName:  certName,
				DNSNames:    []string{certName, "e2etests.invalid"},
				Duration:    &metav1.Duration{Duration: 24 * time.Hour},
				RenewBefore: &metav1.Duration{Duration: 8 * time.Hour},
				IssuerRef: cmmetav1.IssuerReference{
					Name:  t.Name,
					Kind:  gvk.Kind,
					Group: gvk.Group,
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for certificate to become ready")
		_, err = f.Helper().WaitForCertificateReady(cfg.Namespace, certName, timeout)
		Expect(err).NotTo(HaveOccurred())

		return certName
	}

	It("Tests Issuer functionality", func() {
		t := &templateConfig{
			Name:      "issuer-" + util.RandomString(5),
			Namespace: cfg.Namespace,
			Project:   cfg.Project,
			Location:  cfg.Location,
			Pool:      cfg.CaPoolId,
		}
		certName := createIssuerAndCertificate(t, issuerYAML, 10*time.Second)

		By("Verifying chain and CA")
		err := f.Helper().VerifyCMCertificate(cfg.Namespace, certName)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Tests ClusterIssuer functionality", func() {
		t := &templateConfig{
			Name:     "clusterissuer-" + util.RandomString(5),
			Project:  cfg.Project,
			Location: cfg.Location,
			Pool:     cfg.CaPoolId,
		}
		certName := createIssuerAndCertificate(t, clusterIssuerYaml, 10*time.Second)

		By("Verifying chain and CA")
		err := f.Helper().VerifyCMCertificate(cfg.Namespace, certName)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Tests Issuer with CAFetchMode PoolCAs", func() {
		t := &templateConfig{
			Name:        "issuer-poolcas-" + util.RandomString(5),
			Namespace:   cfg.Namespace,
			Project:     cfg.Project,
			Location:    cfg.Location,
			Pool:        cfg.CaPoolId,
			CAFetchMode: "PoolCAs",
		}
		certName := createIssuerAndCertificate(t, issuerWithCAFetchModeYAML, 10*time.Second)

		By("Verifying ca.crt contains multiple CA certificates from pool")
		err := f.Helper().VerifyMultiplePoolCAs(cfg.Namespace, certName)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Tests Issuer failover to fallback CA pool", func() {
		if cfg.FallbackProject == "" || cfg.FallbackCaPoolId == "" || cfg.FallbackLocation == "" {
			Skip("--fallback-project, --fallback-capoolid and --fallback-location are required, skipping failover test")
		}

		t := &templateConfig{
			Name:             "issuer-failover-" + util.RandomString(5),
			Namespace:        cfg.Namespace,
			Project:          cfg.Project,
			Location:         cfg.Location,
			Pool:             "nonexistent-pool-" + util.RandomString(5),
			FallbackProject:  cfg.FallbackProject,
			FallbackCaPoolId: cfg.FallbackCaPoolId,
			FallbackLocation: cfg.FallbackLocation,
		}
		// Use a 30s timeout because failing over from the nonexistent primary pool
		// to the fallback pool requires additional round-trips to Google CAS.
		certName := createIssuerAndCertificate(t, issuerWithFallbackYAML, 30*time.Second)

		By("Verifying chain and CA")
		err := f.Helper().VerifyCMCertificate(cfg.Namespace, certName)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Tests Issuer with fallback CA pool configured", func() {
		if cfg.FallbackProject == "" || cfg.FallbackCaPoolId == "" || cfg.FallbackLocation == "" {
			Skip("--fallback-project, --fallback-capoolid and --fallback-location are required, skipping fallback pool test")
		}

		t := &templateConfig{
			Name:             "issuer-fallback-" + util.RandomString(5),
			Namespace:        cfg.Namespace,
			Project:          cfg.Project,
			Location:         cfg.Location,
			Pool:             cfg.CaPoolId,
			FallbackProject:  cfg.FallbackProject,
			FallbackCaPoolId: cfg.FallbackCaPoolId,
			FallbackLocation: cfg.FallbackLocation,
		}
		certName := createIssuerAndCertificate(t, issuerWithFallbackYAML, 10*time.Second)

		By("Verifying chain and CA")
		err := f.Helper().VerifyCMCertificate(cfg.Namespace, certName)
		Expect(err).NotTo(HaveOccurred())
	})
})
