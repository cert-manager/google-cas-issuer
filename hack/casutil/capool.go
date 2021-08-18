package main

import (
	privateca "cloud.google.com/go/security/privateca/apiv1"
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/api/iterator"
	privatecaapi "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	"os"
	"path"
)

var (
	createPool = &cobra.Command{
		Use:   "pool <name>",
		Short: "Create CA pool",
		Run: func(cmd *cobra.Command, args []string) {
			c, err := privateca.NewCertificateAuthorityClient(context.Background())
			fatalIf(err)
			defer c.Close()

			op, err := c.CreateCaPool(context.Background(), &privatecaapi.CreateCaPoolRequest{
				Parent: fmt.Sprintf(
					"projects/%s/locations/%s",
					viper.GetString("project"),
					viper.GetString("location"),
				),
				CaPoolId: args[0],
				CaPool: &privatecaapi.CaPool{
					Tier:              privatecaapi.CaPool_ENTERPRISE,
					IssuancePolicy:    nil,
					PublishingOptions: nil,
					Labels:            nil,
				},
				RequestId: uuid.New().String(),
			})
			fatalIf(err)

			resp, err := op.Wait(context.Background())
			fatalIf(err)

			fmt.Printf("Created pool %s\n", resp.Name)
		},
		Args: cobra.ExactArgs(1),
	}
	listPool = &cobra.Command{
		Use:   "pools",
		Short: "list all pools in project / location",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := privateca.NewCertificateAuthorityClient(context.Background())
			fatalIf(err)
			defer c.Close()
			it := c.ListCaPools(context.Background(), &privatecaapi.ListCaPoolsRequest{
				Parent: fmt.Sprintf(
					"projects/%s/locations/%s",
					viper.GetString("project"),
					viper.GetString("location"),
				),
			})
			var data [][]string
			for {
				resp, err := it.Next()
				if err == iterator.Done {
					break
				}
				fatalIf(err)
				var tier string
				switch resp.Tier {
				case privatecaapi.CaPool_TIER_UNSPECIFIED:
					tier = "Unspecified"
				case privatecaapi.CaPool_ENTERPRISE:
					tier = "Enterprise"
				case privatecaapi.CaPool_DEVOPS:
					tier = "Devops"
				default:
					tier = fmt.Sprintf("<unknown tier %d>", resp.Tier)
				}
				name := path.Base(resp.Name)
				data = append(data, []string{name, tier})
			}
			t := tablewriter.NewWriter(os.Stdout)
			t.SetHeader([]string{"Name", "Tier"})
			for _, d := range data {
				t.Append(d)
			}
			t.Render()
		},
	}
	deletePool = &cobra.Command{
		Use:   "pool <name>",
		Short: "delete CA pool",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := privateca.NewCertificateAuthorityClient(context.Background())
			fatalIf(err)
			defer c.Close()
			op, err := c.DeleteCaPool(context.Background(), &privatecaapi.DeleteCaPoolRequest{
				Name: fmt.Sprintf(
					"projects/%s/locations/%s/caPools/%s",
					viper.GetString("project"),
					viper.GetString("location"),
					args[0],
				),
				RequestId: uuid.New().String(),
			})
			fatalIf(err)
			err = op.Wait(context.Background())
			// Seems this always errors with
			// mismatched message type: got "google.protobuf.Empty" want "google.cloud.security.privateca.v1.CaPool"
			// but the call succeeds?
			fatalIf(err)
			fmt.Printf("deleted projects/%s/locations/%s/caPools/%s\n", viper.GetString("project"),
				viper.GetString("location"), args[0])
		},
	}
)
