# Google Certificate Authority Service Issuer for cert-manager

This repository contains an [external Issuer](https://cert-manager.io/docs/contributing/external-issuers/)
for cert-manager that issues certificates using Google's private
[certificate authority service](https://cloud.google.com/certificate-authority-service/).

# Usage

Enable the private CA API in your GCP project by following the
[official documentation](https://cloud.google.com/certificate-authority-service/docs/quickstart).

Install cert-manager
```shell
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.0.4/cert-manager.yaml --validate=false
```

Install the CRDs from `config/crd`

```shell
kubectl create -f config/crd
```

If running off GKE or in a different project, create a service account
that has the Private CA - Admin Role in the project that has Google CAS enabled,
download the private key in JSON format and store it in a Kubernetes Secret:

```shell
 kubectl create secret generic googlesa --from-file project-name-keyid.json 
```

If running on GKE, you can skip this step if you bind the correct IAM
roles to your workload service account.

Create a root CA from the dashboard, or other API

Create an Issuer or ClusterIssuer:

```yaml
apiVersion: issuers.jetstack.io/v1alpha1
kind: GoogleCASIssuer
metadata:
  name: googlecasissuer-sample
spec:
  project: project-name
  location: europe-west1
  certificateAuthorityID: demo-root
  # credentials are optional
  credentials:
    name: "googlesa"
    key: "project-name-keyid.json"
```

or

```yaml
apiVersion: issuers.jetstack.io/v1alpha1
kind: GoogleCASClusterIssuer
metadata:
  name: googlecasclusterissuer-sample
spec:
  project: project-name
  location: europe-west1
  certificateAuthorityID: demo-root
  # credentials are optional
  credentials:
    name: "googlesa"
    namespace: "default"
    key: "project-name-keyid.json"
```

Create certificates as normal, but ensure the IssuerRef is set to

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: demo-certificate
  namespace: default
spec:
  # The secret name to store the signed certificate
  secretName: demo-cert-tls
  # Common Name
  commonName: cert-manager.io.demo
  # DNS SAN
  dnsNames:
    - cert-manager.io
    - jetstack.io
  # Duration of the certificate
  duration: 24h
  # Renew 8 hours before the certificate expiration
  renewBefore: 8h
  # Important: Ensure the issuerRef is set to the issuer or cluster issuer configured earlier
  issuerRef:
    group: issuers.jetstack.io
    kind: GoogleCASClusterIssuer
    name: googlecasclusterissuer-sample
```
