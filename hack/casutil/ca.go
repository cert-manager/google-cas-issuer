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
	"google.golang.org/protobuf/types/known/durationpb"
	"os"
	"path"
)

var (
	createCA = &cobra.Command{
		Use:   "ca <name>",
		Short: "Create CA in a pool",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := privateca.NewCertificateAuthorityClient(context.Background())
			fatalIf(err)
			defer c.Close()
			p, err := cmd.Flags().GetString("pool")
			fatalIf(err)
			op, err := c.CreateCertificateAuthority(context.Background(), &privatecaapi.CreateCertificateAuthorityRequest{
				Parent: fmt.Sprintf(
					"projects/%s/locations/%s/caPools/%s",
					viper.GetString("project"),
					viper.GetString("location"),
					p,
				),
				CertificateAuthorityId: args[0],
				CertificateAuthority: &privatecaapi.CertificateAuthority{
					Type: privatecaapi.CertificateAuthority_SELF_SIGNED,
					Config: &privatecaapi.CertificateConfig{
						SubjectConfig: &privatecaapi.CertificateConfig_SubjectConfig{
							Subject: &privatecaapi.Subject{
								CommonName:         args[0],
								CountryCode:        "GB",
								Organization:       "Jetstack",
								OrganizationalUnit: "Product",
								Locality:           "",
								Province:           "",
								StreetAddress:      "",
								PostalCode:         "",
							},
							SubjectAltName: &privatecaapi.SubjectAltNames{
								DnsNames:       args,
								Uris:           nil,
								EmailAddresses: nil,
								IpAddresses:    nil,
								CustomSans:     nil,
							},
						},
						X509Config: &privatecaapi.X509Parameters{
							KeyUsage: &privatecaapi.KeyUsage{
								BaseKeyUsage: &privatecaapi.KeyUsage_KeyUsageOptions{
									DigitalSignature:  true,
									ContentCommitment: true,
									KeyEncipherment:   false,
									DataEncipherment:  false,
									KeyAgreement:      true,
									CertSign:          true,
									CrlSign:           true,
									EncipherOnly:      false,
									DecipherOnly:      false,
								},
								ExtendedKeyUsage: &privatecaapi.KeyUsage_ExtendedKeyUsageOptions{
									ServerAuth:      true,
									ClientAuth:      true,
									CodeSigning:     false,
									EmailProtection: false,
									TimeStamping:    false,
									OcspSigning:     true,
								},
								UnknownExtendedKeyUsages: nil,
							},
							CaOptions: &privatecaapi.X509Parameters_CaOptions{
								IsCa:                truePointer(),
								MaxIssuerPathLength: twoPointer(),
							},
						},
					},
					Lifetime: &durationpb.Duration{
						// 10 Years
						Seconds: 315569520,
						Nanos:   0,
					},
					KeySpec: &privatecaapi.CertificateAuthority_KeyVersionSpec{
						KeyVersion: &privatecaapi.CertificateAuthority_KeyVersionSpec_CloudKmsKeyVersion{
							// TODO: make keyrings configurable
							CloudKmsKeyVersion: fmt.Sprintf(
								"projects/%s/locations/%s/keyRings/kr1/cryptoKeys/k1/cryptoKeyVersions/1",
								viper.GetString("project"),
								viper.GetString("location"),
							),
						},
					},
				},
				RequestId: uuid.New().String(),
			})
			fatalIf(err)
			resp, err := op.Wait(context.Background())
			fatalIf(err)
			fmt.Printf("Created %s\n", resp.Name)
		},
	}
	listCA = &cobra.Command{
		Use:   "cas",
		Short: "List all CAs in pool",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := privateca.NewCertificateAuthorityClient(context.Background())
			fatalIf(err)
			defer c.Close()
			p, err := cmd.Flags().GetString("pool")
			fatalIf(err)
			it := c.ListCertificateAuthorities(context.Background(), &privatecaapi.ListCertificateAuthoritiesRequest{
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
				var tier string
				switch resp.Tier {
				case privatecaapi.CaPool_TIER_UNSPECIFIED:
					tier = "Unspecified"
				case privatecaapi.CaPool_ENTERPRISE:
					tier = "Enterprise"
				case privatecaapi.CaPool_DEVOPS:
					tier = "Devops"
				default:
					tier = fmt.Sprintf("<unknown tier %s>", resp.Tier.String())
				}
				state := resp.State.String()
				data = append(data, []string{name, tier, state})
			}
			t := tablewriter.NewWriter(os.Stdout)
			t.SetHeader([]string{"Name", "Tier", "State"})
			for _, d := range data {
				t.Append(d)
			}
			t.Render()
		},
	}
	deleteCA = &cobra.Command{
		Use:   "ca <name>",
		Short: "Delete a CA in a pool",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := privateca.NewCertificateAuthorityClient(context.Background())
			fatalIf(err)
			defer c.Close()
			p, err := cmd.Flags().GetString("pool")
			fatalIf(err)
			op, err := c.DeleteCertificateAuthority(context.Background(), &privatecaapi.DeleteCertificateAuthorityRequest{
				Name: fmt.Sprintf(
					"projects/%s/locations/%s/caPools/%s/certificateAuthorities/%s",
					viper.GetString("project"),
					viper.GetString("location"),
					p,
					args[0],
				),
				RequestId:                uuid.New().String(),
				IgnoreActiveCertificates: true,
			})
			fatalIf(err)
			resp, err := op.Wait(context.Background())
			fatalIf(err)
			fmt.Printf("deleted %s\n", resp.Name)
		},
	}
	enableCA = &cobra.Command{
		Use:   "ca <name>",
		Short: "Enables a CA in a Pool",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			c, err := privateca.NewCertificateAuthorityClient(context.Background())
			fatalIf(err)
			defer c.Close()
			p, err := cmd.Flags().GetString("pool")
			fatalIf(err)
			op, err := c.EnableCertificateAuthority(context.Background(), &privatecaapi.EnableCertificateAuthorityRequest{
				Name: fmt.Sprintf(
					"projects/%s/locations/%s/caPools/%s/certificateAuthorities/%s",
					viper.GetString("project"),
					viper.GetString("location"),
					p,
					args[0],
				),
				RequestId: uuid.New().String(),
			})
			fatalIf(err)
			resp, err := op.Wait(context.Background())
			fatalIf(err)
			fmt.Printf("Enabled %s\n", resp.Name)
		},
	}
)

func truePointer() *bool {
	t := true
	return &t
}

func twoPointer() *int32 {
	two := int32(2)
	return &two
}
