package main

import (
	privateca "cloud.google.com/go/security/privateca/apiv1"
	"context"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/api/iterator"
	privatecaapi "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	"os"
	"path"
	"time"
)

var (
	listCerts = &cobra.Command{
		Use:   "certs",
		Short: "Lists certificates in a pool",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			p, err := cmd.Flags().GetString("pool")
			fatalIf(err)
			c, err := privateca.NewCertificateAuthorityClient(context.Background())
			fatalIf(err)
			defer c.Close()
			it := c.ListCertificates(context.Background(), &privatecaapi.ListCertificatesRequest{
				Parent: fmt.Sprintf(
					"projects/%s/locations/%s/caPools/%s",
					viper.GetString("project"),
					viper.GetString("location"),
					p,
				),
			})
			var data [][]string
			for {
				resp, err := it.Next()
				if err == iterator.Done {
					break
				}
				fatalIf(err)
				name := path.Base(resp.Name)
				cn := resp.CertificateDescription.SubjectDescription.Subject.CommonName
				sans := resp.CertificateDescription.SubjectDescription.SubjectAltName.String()
				created := resp.CreateTime.AsTime().Local().Truncate(time.Second).String()
				lifetime := resp.Lifetime.AsDuration().String()
				data = append(data, []string{name, cn, sans, created, lifetime})
			}
			t := tablewriter.NewWriter(os.Stdout)
			t.SetHeader([]string{"Name", "CN", "SANs", "Created", "Lifetime"})
			for _, d := range data {
				t.Append(d)
			}
			t.Render()
		},
	}
)
