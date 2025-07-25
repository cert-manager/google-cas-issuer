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

package cmd

import (
	"flag"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	issuersv1beta1 "github.com/cert-manager/google-cas-issuer/api/v1beta1"
	controllers "github.com/cert-manager/google-cas-issuer/pkg/controllers"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

var (
	rootCmd = &cobra.Command{
		Use:   "google-cas-issuer",
		Short: "An external issuer for cert-manager that signs certificates with Google CAS",
		Long:  "An external issuer for cert-manager that signs certificates with Google CAS.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root()
		},
	}
)

func init() {
	// Issuer flags
	rootCmd.PersistentFlags().String("metrics-addr", ":8080", "The address the metric endpoint binds to.")
	rootCmd.PersistentFlags().Bool("enable-leader-election", false, "Enable leader election for controller manager.")
	rootCmd.PersistentFlags().String("leader-election-id", "cm-google-cas-issuer", "The ID of the leader election lock that the controller should attempt to acquire.")
	rootCmd.PersistentFlags().String("cluster-resource-namespace", "cert-manager", "The namespace for secrets in which cluster-scoped resources are found.")
	rootCmd.PersistentFlags().Bool("disable-approval-check", false, "Don't check whether a CertificateRequest is approved before signing. For compatibility with cert-manager <v1.3.0.")

	rootCmd.PersistentFlags().StringP("log-level", "v", "1", "Log level (1-5).")

	viper.BindPFlags(rootCmd.PersistentFlags())
}

func root() error {
	klog.InitFlags(nil)
	log := klogr.New()
	flag.Set("v", viper.GetString("log-level"))
	ctrl.SetLogger(log)

	// Add all APIs to scheme
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		setupLog.Error(err, "couldn't add client-go scheme")
		return err
	}
	if err := cmapi.AddToScheme(scheme); err != nil {
		setupLog.Error(err, "couldn't add cert-manager scheme")
		return err
	}
	if err := issuersv1beta1.AddToScheme(scheme); err != nil {
		setupLog.Error(err, "couldn't add cert-manager scheme")
		return err
	}

	// Create controller-manager
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: viper.GetString("metrics-addr"),
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port: 9443,
		}),
		LeaderElection:   viper.GetBool("enable-leader-election"),
		LeaderElectionID: viper.GetString("leader-election-id"),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return err
	}

	ctx := ctrl.SetupSignalHandler()

	// Start Controllers
	if err = (&controllers.GoogleCAS{
		MaxRetryDuration: 30 * time.Second,
	}).SetupWithManager(ctx, mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GoogleCASIssuer")
		return err
	}
	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		return err
	}
	return nil
}
