# Google Certificate Authority Service Issuer for cert-manager

This repository contains an [external Issuer](https://cert-manager.io/docs/contributing/external-issuers/)
for cert-manager that issues certificates using Google's private
[certificate authority service](https://cloud.google.com/certificate-authority-service/).

# Usage

## Prerequisites

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

## IAM setup

Firstly, create a Google Cloud IAM service account

```shell
gcloud iam service-accounts create my-sa
```

Apply the appropriate IAM bindings to this account. This example
gives full access to CAS, but you can restrict it as necessary.

```shell
gcloud iam service-accounts add-iam-policy-binding my-sa@project-id.iam.gserviceaccount.com \
--role=roles/privateca.admin
```

### Inside GKE with workload identity

Ensure your cluster is set up with
[workload identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
enabled. Create a kubernetes service account for the CAS Issuer:

```shell
# Create a new Kubernetes service account
kubectl create serviceaccount -n cert-manager my-ksa
```

Bind the Kubernetes service account to the Google Cloud service account:

```shell
gcloud iam service-accounts add-iam-policy-binding \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:project-id.svc.id.goog[cert-manager/my-ksa]" \
  my-sa@project-id.iam.gserviceaccount.com

kubectl annotate serviceaccount \
  --namespace cert-manager \
  my-ksa \
  iam.gke.io/gcp-service-account=my-sa@project-id.iam.gserviceaccount.com
```

### Outside GKE or in an unrelated GCP Project

Download the private key in JSON format for the service account you created earlier,
then store it in a Kubernetes secret.

```shell
 kubectl -n cert-manager create secret generic googlesa --from-file project-name-keyid.json 
```

## Issuer setup

Create a root CA from the Google dashboard, or other API - refer to the
[official documentation](https://cloud.google.com/certificate-authority-service/docs/creating-certificate-authorities)

Create an Issuer or ClusterIssuer:

```yaml
apiVersion: cas-issuer.jetstack.io/v1alpha1
kind: GoogleCASIssuer
metadata:
  name: googlecasissuer-sample
spec:
  project: project-name
  location: europe-west1
  certificateAuthorityID: demo-root
  # credentials are optional if workload identity is enabled
  credentials:
    name: "googlesa"
    key: "project-name-keyid.json"
```

or

```yaml
apiVersion: cas-issuer.jetstack.io/v1alpha1
kind: GoogleCASClusterIssuer
metadata:
  name: googlecasclusterissuer-sample
spec:
  project: project-name
  location: europe-west1
  certificateAuthorityID: demo-root
  # credentials are optional if workload identity is enabled
  credentials:
    name: "googlesa"
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
