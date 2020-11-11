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

Install the CAS Issuer CRDs in `config/crd`. These manifests use kustomization (hence the `-k` option).

```shell
kubectl apply -k config/crd
```

## IAM setup

Firstly, create a Google Cloud IAM service account.

```shell
gcloud iam service-accounts create my-sa
```

Apply the appropriate IAM bindings to this account. This example
gives full access to CAS, but you can restrict it as necessary (see [Predefined Roles](https://cloud.google.com/certificate-authority-service/docs/reference/permissions-and-roles#predefined_roles) for more details).

```shell
gcloud iam service-accounts add-iam-policy-binding my-sa@project-id.iam.gserviceaccount.com \
--role=roles/privateca.admin
```

You can now create a service account key and download it to a JSON file.

```shell
gcloud iam service-accounts keys create project-name-keyid.json --iam-account my-sa@project-id.iam.gserviceaccount.com
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

### Kubernetes RBAC rules

Examine the ClusterRole and ClusterRolebinding in `config/rbac/role.yaml` and
`config/rbac/role_binding.yaml`. By default, these give the default Kubernetes service
account in the cert-manager namespace all the necessary permissions. Customise these to your needs.

```shell
kubectl apply -f config/rbac/role.yaml
kubectl apply -f config/rbac/role_binding.yaml
```

### Build and Deploy the controller

To build the image, ensure you have
[kubebuilder inbstalled](https://book.kubebuilder.io/quick-start.html#installation).

Build the docker image:

```shell
make docker-build
```

Push the docker image or load it into kind for testing
```shell
make docker-push || kind load docker-image quay.io/jetstack/cert-manager-google-cas-issuer:latest
```

Deploy the issuer controller:
```shell
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: google-cas-issuer
  namespace: cert-manager
  labels:
    app: google-cas-issuer
spec:
  selector:
    matchLabels:
      app: google-cas-issuer
  replicas: 1
  template:
    metadata:
      labels:
        app: google-cas-issuer
    spec:
      containers:
      - image: quay.io/jetstack/cert-manager-google-cas-issuer:latest
        imagePullPolicy: IfNotPresent
        name: google-cas-issuer
        resources:
          limits:
            cpu: 100m
            memory: 30Mi
          requests:
            cpu: 100m
            memory: 20Mi
      terminationGracePeriodSeconds: 10
EOF
```

### Configure Issuer

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
    group: cas-issuer.jetstack.io
    kind: GoogleCASClusterIssuer
    name: googlecasclusterissuer-sample
```
