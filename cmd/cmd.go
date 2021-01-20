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
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

// Execute is the main entrypoint
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		setupLog.Error(err, "error in root cmd")
		os.Exit(1)
	}
}

func init() {
	// Check environment variables for config
	cobra.OnInitialize(flagsFromEnv)

	// initialise psuedorandom numbers for cert IDs
	rand.Seed(time.Now().UnixNano())
}

// flagsFromEnv allows flags to be set from environment variables.
// for example --metrics-addr can be set with GOOGLE_CAS_ISSUER_METRICS_ADDR
func flagsFromEnv() {
	viper.SetEnvPrefix("google_cas_issuer")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}
