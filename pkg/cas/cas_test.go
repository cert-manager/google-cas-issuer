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

package cas

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	casapi "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
)

// unitTestClient is a pretend CAS signer for running unit tests offline
type unitTestClient struct {
	CAs map[string]certKeyPair
	sync.RWMutex
}

type certKeyPair struct {
	key  []byte
	cert []byte
}

func (u *unitTestClient) CreateCA(options *CreateCAOptions) error {
	u.Lock()
	defer u.Unlock()
	if u.CAs == nil {
		u.CAs = make(map[string]certKeyPair)
	}
	if err := sanityCheckCAOptions(options); err != nil {
		return err
	}
	if _, exists := u.CAs[options.CertificateAuthorityID]; exists {
		return CaAlreadyExistsError
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	notBefore := time.Now()
	notAfter := notBefore.Add(options.Expiry)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"GB"},
			Organization:       []string{"Jetstack"},
			OrganizationalUnit: []string{"CAS Issuer Unit Tests"},
			CommonName:         options.CertificateAuthorityID,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	cert := &bytes.Buffer{}
	if err := pem.Encode(cert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write data to cert buffer: %v", err)
	}
	key := &bytes.Buffer{}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err := pem.Encode(key, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return fmt.Errorf("failed to write data to key.pem: %v", err)
	}
	u.CAs[options.CertificateAuthorityID] = certKeyPair{
		key:  key.Bytes(),
		cert: cert.Bytes(),
	}
	return nil
}

func (u *unitTestClient) ListCA(options *ListCAOptions) ([]string, error) {
	u.RLock()
	defer u.RUnlock()
	var cas []string
	if u.CAs == nil {
		return []string{}, nil
	}
	for ca := range u.CAs {
		cas = append(cas, ca)
	}
	return cas, nil
}

func (u *unitTestClient) CreateCertificate(options *CreateCertificateOptions) (string, []string, error) {
	block, _ := pem.Decode(options.CSR)
	if block == nil {
		return "", nil, errors.New("no PEM data found in CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	exp := time.Now().Add(24 * time.Hour)
	if options.Expiry != 0 {
		exp = time.Now().Add(options.Expiry)
	}
	cert := &x509.Certificate{
		BasicConstraintsValid: true,
		Version:               csr.Version,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		IsCA:                  false,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              exp,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		EmailAddresses:        csr.EmailAddresses,
	}
	u.RLock()
	defer u.RUnlock()
	caCertPair, exists := u.CAs[options.CertificateID]
	if !exists {
		return "", nil, errors.New("ca " + options.CertificateID + " does not exist")
	}
	caKeyBlock, _ := pem.Decode(caCertPair.key)
	if caKeyBlock == nil {
		return "", nil, errors.New("ca " + options.CertificateID + " key is invalid PEM")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return "", nil, errors.New("ca " + options.CertificateID + " key is invalid")
	}
	caSigner, ok := caKey.(crypto.Signer)
	if !ok {
		return "", nil, errors.New("ca " + options.CertificateID + " key is not a valid signer")
	}
	caCertBlock, _ := pem.Decode(caCertPair.cert)
	if caCertBlock == nil {
		return "", nil, errors.New("ca " + options.CertificateID + " cert is invalid PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return "", nil, errors.New("ca " + options.CertificateID + " cert is invalid")
	}
	signedCertDER, err := x509.CreateCertificate(rand.Reader, cert, caCert, cert.PublicKey, caSigner)
	signedCertPEM := &bytes.Buffer{}
	if err := pem.Encode(signedCertPEM, &pem.Block{Type: "CERTIFICATE", Bytes: signedCertDER}); err != nil {
		return "", nil, err
	}
	return signedCertPEM.String(), []string{string(caCertPair.cert)}, nil
}

func sanityCheckCAOptions(options *CreateCAOptions) error {
	if options.CertificateAuthorityID == "" {
		return errors.New("certificate id required")
	}
	if options.Expiry == 0 {
		return errors.New("expiry required")
	}
	if options.Subject == nil {
		return errors.New("subject required")
	}
	if options.Parent == "" {
		return errors.New("parent required")
	}
	return nil
}

func TestCasClient_Unit(t *testing.T) {
	var client Client = &unitTestClient{}
	testCreateOpts := &CreateCAOptions{
		CertificateAuthorityID: "unit-test",
		Subject: &casapi.Subject{
			CountryCode:        "GB",
			Organization:       "Jetstack",
			OrganizationalUnit: "cert-manager",
		},
		Parent:          "projects/jetstack-cas/locations/europe-west1",
		SubjectAltNames: nil,
		Expiry:          24 * time.Hour,
	}
	if err := client.CreateCA(testCreateOpts); err != nil {
		t.Errorf("CreateCA fail: %v", err)
	}
	if err := client.CreateCA(testCreateOpts); err != CaAlreadyExistsError {
		t.Errorf("Expected %v, got %v", CaAlreadyExistsError, err)
	}
	CAs, err := client.ListCA(&ListCAOptions{
		Parent: "projects/jetstack-cas/locations/europe-west1",
	})
	if err != nil {
		t.Errorf("ListCA failed: %v", err)
	}
	found := false
	for _, ca := range CAs {
		if ca == "unit-test" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CreateCA didn't create unit-test")
	}
	testCSR := `-----BEGIN CERTIFICATE REQUEST-----
MIICtTCCAZ0CAQAwcDELMAkGA1UEBhMCR0IxETAPBgNVBAoMCEpldHN0YWNrMRUw
EwYDVQQLDAxjZXJ0LW1hbmFnZXIxFjAUBgNVBAMMDXVuaXQtdGVzdC1jc3IxHzAd
BgkqhkiG9w0BCQEWEHRlc3RAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDIZsZUiv5ay5GLBfvu6JWYm6PdS4oOgC7lDlxq1D56VTF6
JSXJsri3FX1gwWcnR1LCeAbEJ1zmQBNC5GDytWE+I0rTDjyxF2JNzv71dVzMy3xe
4a557f8hd+c2+4hfqIkGwkQ7pdis8nHvaTXYq7i/FiPnqO7zv4OB5su2IYmKubrH
9bOIBYEjRAxPW67Kzy/Y9W4jQKbLmsyXrUac/IuXRWPlT9Dfb0f3bKGnH3HUo0jC
SqLB4FhID64Tdj6R8zSRvzwe+6WgaeEvfkzDVpBDp8vrW2eNhU12lx26RC/S3E1U
JOnLWkdvC+g51blWb4XscbGs7yBBNBjBCW5PjcdnAgMBAAGgADANBgkqhkiG9w0B
AQsFAAOCAQEAgEL4ROxT2X6N9WhdutQVcZcnoS8c3SSM038fKadn+h1NQTBJ/X9n
lR9Fphiy8JAAxM+yKUJoS2nZ5CpVf25OebAfRLSvJEPLhEuHPuRtgbXPlX2NuSoI
0qHjR40vYPiNES0TDPa+gpL1DspkwxjvoKGYGMpqs2Llz/9I5uQeyEiqCKCo7Sh2
VvBmzBt/dKhw+YzKMHVxaFaA+GE/gLpYZYwa9PSfSfqjlQ8cxzf3HOUw+iLmGeoY
hu1drCBboquyGPpdJBxMwnGOwORHl3/7kO04GWwkVTXR1qhnvfi5Cc0ZRpZ6N/Ei
slZRcEAfkzoAvOamtHyMowVWQSYfIAXRvg==
-----END CERTIFICATE REQUEST-----`
	createCertOpts := &CreateCertificateOptions{
		Parent:        "projects/jetstack-cas/locations/europe-west1/certificateAuthorities/unit-test",
		CertificateID: "unit-test",
		CSR:           []byte(testCSR),
	}
	cert, chain, err := client.CreateCertificate(createCertOpts)
	if err != nil {
		t.Errorf("Expected a signed certificate, got error %v", err)
	}
	verifyRoots := x509.NewCertPool()
	if ok := verifyRoots.AppendCertsFromPEM([]byte(chain[0])); !ok {
		t.Errorf("Couldn't add chain to trusted roots")
	}
	verifyCertBlock, _ := pem.Decode([]byte(cert))
	if verifyCertBlock == nil {
		t.Errorf("Couldn't decode signed cert PEM")
	}
	verifyCert, err := x509.ParseCertificate(verifyCertBlock.Bytes)
	if err != nil {
		t.Errorf("Couldn't parse signed cert: %v", err)
	}
	if _, err = verifyCert.Verify(x509.VerifyOptions{
		Roots: verifyRoots,
	}); err != nil {
		t.Errorf("Couldn't verify signed cert: %v", err)
	}
}
