/*
Copyright 2021 The cert-manager Authors.

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

package helper

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmversioned "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type Helper struct {
	cmClient      cmversioned.Interface
	kubeClient    kubernetes.Interface
	dynamicClient dynamic.Interface
}

func NewHelper(cmclient cmversioned.Interface, kubeclient kubernetes.Interface, dynamicClient dynamic.Interface) *Helper {
	return &Helper{
		cmClient:      cmclient,
		kubeClient:    kubeclient,
		dynamicClient: dynamicClient,
	}
}

// WaitForCertificateReady waits for the certificate resource to enter a Ready
// state.
func (h *Helper) WaitForCertificateReady(ns, name string, timeout time.Duration) (*cmapi.Certificate, error) {
	var certificate *cmapi.Certificate

	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			certificate, err = h.cmClient.CertmanagerV1().Certificates(ns).Get(context.TODO(), name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %s: %v", name, err)
			}
			isReady := apiutil.CertificateHasCondition(certificate, cmapi.CertificateCondition{
				Type:   cmapi.CertificateConditionReady,
				Status: cmmeta.ConditionTrue,
			})
			if !isReady {
				return false, nil
			}
			return true, nil
		},
	)

	// return certificate even when error to use for debugging
	return certificate, err
}

// WaitForPodsReady waits for all pods in a namespace to become ready
func (h *Helper) WaitForPodsReady(ns string, timeout time.Duration) error {
	podsList, err := h.kubeClient.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, pod := range podsList.Items {
		err := wait.PollImmediate(time.Second, timeout,
			func() (bool, error) {
				var err error
				pod, err := h.kubeClient.CoreV1().Pods(ns).Get(context.TODO(), pod.Name, metav1.GetOptions{})
				if err != nil {
					return false, fmt.Errorf("error getting Pod %q: %v", pod.Name, err)
				}
				for _, c := range pod.Status.Conditions {
					if c.Type == corev1.PodReady {
						return c.Status == corev1.ConditionTrue, nil
					}
				}

				return false, nil
			},
		)

		if err != nil {
			return fmt.Errorf("failed to wait for pod %q to become ready: %s",
				pod.Name, err)
		}
	}

	return nil
}

// WaitForUnstructuredReady waits for an unstructured.Unstructured object to become ready
func (h *Helper) WaitForUnstructuredReady(dr dynamic.NamespaceableResourceInterface, name, namespace string, timeout time.Duration) error {
	err := wait.PollImmediate(time.Second, timeout, func() (done bool, err error) {
		var obj *unstructured.Unstructured
		if len(namespace) > 0 {
			obj, err = dr.Namespace(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		} else {
			obj, err = dr.Get(context.TODO(), name, metav1.GetOptions{})
		}
		if err != nil {
			return true, err
		}
		status, found, err := unstructured.NestedMap(obj.Object, "status")
		if err != nil {
			return false, err
		}
		if !found {
			return false, nil
		}
		conditions, ok := status["conditions"].([]interface{})
		if !ok {
			return false, errors.New(".status.conditions is not []interface{}")
		}
		for _, c := range conditions {
			cond, ok := c.(map[string]interface{})
			if !ok {
				return false, errors.New(".status.conditions doesn't contain a map")
			}
			if cond["type"].(string) != "Ready" {
				continue
			}
			if cond["status"].(string) == "True" {
				return true, nil
			} else {
				reasonMessage := "Issuer is not ready: "
				reason, found := cond["reason"]
				if found {
					reasonMessage = reasonMessage + " " + reason.(string)
				}
				message, found := cond["message"]
				if found {
					reasonMessage = reasonMessage + " " + message.(string)
				}
				return false, errors.New(reasonMessage)
			}
		}
		return false, nil
	})

	return err
}

func (h *Helper) VerifyCMCertificate(namespace, name string) error {
	certificate, err := h.cmClient.CertmanagerV1().Certificates(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("couldn't get certificate %s/%s: %w", namespace, name, err)
	}

	if certificate == nil {
		return errors.New("certificate is nil")
	}
	secret, err := h.kubeClient.CoreV1().Secrets(certificate.ObjectMeta.Namespace).Get(context.TODO(), certificate.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("couldn't retrieve secret %s/%s: %w", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName, err)
	}

	caCrt, found := secret.Data["ca.crt"]
	if !found {
		return fmt.Errorf("ca.crt not found in secret %s/%s", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName)
	}
	tlsCrt, found := secret.Data["tls.crt"]
	if !found {
		return fmt.Errorf("tls.crt not found in secret %s/%s", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName)
	}
	tlsKey, found := secret.Data["tls.key"]
	if !found {
		return fmt.Errorf("tls.key not found in secret %s/%s", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName)
	}

	cert, err := tls.X509KeyPair(tlsCrt, tlsKey)
	if err != nil {
		return fmt.Errorf("certificate in secret %s/%s is invalid: %w", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName, err)
	}

	caBlock, rest := pem.Decode(caCrt)
	if len(rest) > 0 {
		return fmt.Errorf("ca in secret %s/%s has more than one PEM block or no valid PEM was found", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName)
	}
	if caBlock == nil {
		return fmt.Errorf("while parsing ca.crt, no ca found in secret %s/%s", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName)
	}

	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("ca in secret %s/%s is invalid: %w", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName, err)
	}

	// each cert in a chain must certify the one preceding it
	for i := range len(cert.Certificate) - 1 {
		certifier, err := x509.ParseCertificate(cert.Certificate[i+1])
		if err != nil {
			return fmt.Errorf("tls.crt in secret %s/%s has invalid cert at %d in chain: %w", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName, i+1, err)
		}
		certified, err := x509.ParseCertificate(cert.Certificate[i])
		if err != nil {
			return fmt.Errorf("tls.crt in secret %s/%s has invalid cert at %d in chain: %w", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName, i, err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(certifier)

		if _, err = certified.Verify(x509.VerifyOptions{
			Roots:       pool,
			CurrentTime: time.Now(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return fmt.Errorf("tls.crt in secret %s/%s: cert at %d in chain couldn't be verified: %w", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName, i, err)
		}
	}
	// verify last in chain against root
	certified, err := x509.ParseCertificate(cert.Certificate[len(cert.Certificate)-1])
	if err != nil {
		return fmt.Errorf("tls.cert in secret %s/%s has invalid cert at %d in chain: %w", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName, len(cert.Certificate)-1, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err = certified.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("ca.crt in secret %s/%s doesn't validate tls.crt: %w", certificate.ObjectMeta.Namespace, certificate.Spec.SecretName, err)
	}

	return nil
}
