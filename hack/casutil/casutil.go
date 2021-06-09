package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	root = &cobra.Command{
		Use:   "casutil",
		Short: "Utility for Interacting with the Google CAS v1 API",
	}
	create = &cobra.Command{
		Use:   "create",
		Short: "create CAs and CA pools",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			showConfig()
		},
	}
	list = &cobra.Command{
		Use:   "list",
		Short: "List pools or CAs in a pool",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			showConfig()
		},
	}
	delete = &cobra.Command{
		Use:   "delete",
		Short: "Delete pools or CAs in a pool",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			showConfig()
		},
	}
	enable = &cobra.Command{
		Use:   "enable",
		Short: "Enable CAs",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			showConfig()
		},
	}
)

func main() {
	root.Execute()
}

func init() {
	cobra.OnInitialize(flagsFromEnv)
	root.PersistentFlags().StringP("project", "p", "", "The GCP project in which CAS operations are performed")
	root.PersistentFlags().StringP("location", "l", "", "The GCP location")

	createCA.Flags().String("pool", "", "The pool to create the CA in")
	listCA.Flags().String("pool", "", "The pool to list CAs in")
	deleteCA.Flags().String("pool", "", "The pool to list CAs in")
	enableCA.Flags().String("pool", "", "The pool to enable CAs in")

	listCerts.Flags().String("pool", "", "The pool to list CAs in")

	create.AddCommand(createPool, createCA)
	list.AddCommand(listPool, listCA, listCerts)
	delete.AddCommand(deletePool, deleteCA)
	enable.AddCommand(enableCA)
	root.AddCommand(create, list, delete, enable)
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

func flagsFromEnv() {
	viper.SetEnvPrefix("casutil")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

func showConfig() {
	fmt.Fprintf(os.Stderr,
		"Using project: %s\n"+
			"Using location: %s\n",
		viper.GetString("project"),
		viper.GetString("location"),
	)
}
