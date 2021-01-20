/*
Copyright 2020 the cert-manager authors.

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
	"crypto/rand"
	"math/big"
	"os"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"

	issuersv1alpha1 "github.com/jetstack/google-cas-issuer/api/v1alpha1"
	"github.com/jetstack/google-cas-issuer/pkg/controller/certificaterequest"
	"github.com/jetstack/google-cas-issuer/pkg/controller/issuer"
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
	rootCmd.PersistentFlags().String("metrics-addr", ":8080", "The address the metric endpoint binds to.")
	rootCmd.PersistentFlags().Bool("enable-leader-election", false, "Enable leader election for controller manager.")
	rootCmd.PersistentFlags().String("cluster-resource-namespace", "cert-manager", "The namespace for secrets in which cluster-scoped resources are found.")
	viper.BindPFlags(rootCmd.PersistentFlags())
}

func root() error {
	// Add all APIs to scheme
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		setupLog.Error(err, "couldn't add client-go scheme")
		return err
	}
	if err := cmapi.AddToScheme(scheme); err != nil {
		setupLog.Error(err, "couldn't add cert-manager scheme")
		return err
	}
	if err := issuersv1alpha1.AddToScheme(scheme); err != nil {
		setupLog.Error(err, "couldn't add cert-manager scheme")
		return err
	}

	// Get the hostname for leader election
	hostname, err := os.Hostname()
	if err != nil {
		// fall back to a random number
		random, err := rand.Int(rand.Reader, big.NewInt(999999999999))
		if err != nil {
			setupLog.Error(err, "unable to get a suitable leader election id")
			os.Exit(1)
		}
		hostname = random.String()
	}

	// Create controller-manager
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: viper.GetString("metrics-addr"),
		Port:               9443,
		LeaderElection:     viper.GetBool("enable-leader-election"),
		LeaderElectionID:   hostname,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return err
	}

	ctx := ctrl.SetupSignalHandler()

	// Start Controllers
	if err = (&issuer.GoogleCASIssuerReconciler{
		Kind:   "GoogleCASIssuer",
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controller").WithName("GoogleCASIssuer"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GoogleCASIssuer")
		return err
	}
	if err = (&issuer.GoogleCASIssuerReconciler{
		Kind:   "GoogleCASClusterIssuer",
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controller").WithName("GoogleCASClusterIssuer"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GoogleCASClusterIssuer")
		return err
	}
	if err = (&certificaterequest.CertificateRequestReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controller").WithName("CertificateRequest"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CertificateRequest")
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
