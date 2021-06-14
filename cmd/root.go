/*
Copyright 2021 Jetstack Ltd.

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
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	issuersv1beta1 "github.com/jetstack/google-cas-issuer/api/v1beta1"
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
	// Issuer flags
	rootCmd.PersistentFlags().String("metrics-addr", ":8080", "The address the metric endpoint binds to.")
	rootCmd.PersistentFlags().Bool("enable-leader-election", false, "Enable leader election for controller manager.")
	rootCmd.PersistentFlags().String("leader-election-id", "cm-google-cas-issuer", "Enable leader election for controller manager.")
	rootCmd.PersistentFlags().String("cluster-resource-namespace", "cert-manager", "The namespace for secrets in which cluster-scoped resources are found.")
	rootCmd.PersistentFlags().Bool("disable-approval-check", false, "Don't check whether a CertificateRequest is approved before signing. For compatibility with cert-manager <v1.3.0.")

	// Zap flags
	rootCmd.PersistentFlags().Bool("zap-devel", false, "Zap Development Mode defaults(encoder=consoleEncoder,logLevel=Debug,stackTraceLevel=Warn).")

	viper.BindPFlags(rootCmd.PersistentFlags())
}

func root() error {
	// Initialise Logging
	opts := &zap.Options{}
	opts.Development = viper.GetBool("zap-devel")
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(opts)))

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
		Scheme:             scheme,
		MetricsBindAddress: viper.GetString("metrics-addr"),
		Port:               9443,
		LeaderElection:     viper.GetBool("enable-leader-election"),
		LeaderElectionID:   viper.GetString("leader-election-id"),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return err
	}

	ctx := ctrl.SetupSignalHandler()

	// Start Controllers
	if err = (&issuer.GoogleCASIssuerReconciler{
		Kind:     "GoogleCASIssuer",
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controller").WithName("GoogleCASIssuer"),
		Recorder: mgr.GetEventRecorderFor("cas-issuer-googlecasissuer-controller"),
		Scheme:   mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GoogleCASIssuer")
		return err
	}
	if err = (&issuer.GoogleCASIssuerReconciler{
		Kind:     "GoogleCASClusterIssuer",
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controller").WithName("GoogleCASClusterIssuer"),
		Recorder: mgr.GetEventRecorderFor("cas-issuer-googlecasclusterissuer-controller"),
		Scheme:   mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GoogleCASClusterIssuer")
		return err
	}
	if err = (&certificaterequest.CertificateRequestReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controller").WithName("CertificateRequest"),
		Recorder: mgr.GetEventRecorderFor("cas-issuer-certificaterequest-controller"),
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
