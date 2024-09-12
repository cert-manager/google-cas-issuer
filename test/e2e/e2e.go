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

package e2e

import (
	"context"
	"flag"
	"os"

	. "github.com/onsi/ginkgo/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/cert-manager/google-cas-issuer/test/e2e/framework/config"
	"github.com/cert-manager/google-cas-issuer/test/e2e/util"
)

var (
	cfg           = config.GetConfig()
	kubeClientSet kubernetes.Interface
)

func init() {
	cfg.AddFlags(flag.CommandLine)
}

var _ = SynchronizedBeforeSuite(func() []byte {
	var err error
	cfg.RepoRoot, err = os.Getwd()
	if err != nil {
		klog.Fatal(err)
	}

	cfg.Namespace = "casissuer-e2e-" + util.RandomString(5)

	if err := cfg.Validate(); err != nil {
		klog.Fatalf("Invalid test config: %s", err)
	}

	clientConfigFlags := genericclioptions.NewConfigFlags(true)
	clientConfigFlags.KubeConfig = &cfg.KubeConfigPath
	config, err := clientConfigFlags.ToRESTConfig()
	if err != nil {
		klog.Fatalf("Invalid kube config: %s", err)
	}
	kubeClientSet, err = kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Couldn't construct client set: %s", err)
	}
	_, err = kubeClientSet.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace}}, metav1.CreateOptions{})
	if err != nil {
		klog.Fatalf("Couldn't create namespace %s: %s", cfg.Namespace, err)
	}
	return nil
}, func([]byte) {
})

var _ = SynchronizedAfterSuite(func() {},
	func() {
		if kubeClientSet == nil {
			return
		}
		_ = kubeClientSet.CoreV1().Namespaces().Delete(context.TODO(), cfg.Namespace, metav1.DeleteOptions{})
	},
)
