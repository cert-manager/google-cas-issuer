# Google Certificate Authority Service Issuer for cert-manager

This repository contains an [external Issuer](https://cert-manager.io/docs/contributing/external-issuers/)
for cert-manager that issues certificates using Google's private
[Certificate Authority Service](https://cloud.google.com/certificate-authority-service/).

## Getting started

### Prerequisites

#### Private CA-enabled GCP project

Enable the private CA API in your GCP project by following the
[official documentation](https://cloud.google.com/certificate-authority-service/docs/quickstart).

#### CAS-managed CAs

You can create a root certificate authority as well as an intermediate
certificate authority ("subordinate") in your current Google project with:

```sh
gcloud beta privateca roots create my-ca --subject="CN=root,O=my-ca"
gcloud beta privateca subordinates create my-sub-ca  --issuer=my-ca --location us-east1 --subject="CN=intermediate,O=my-ca,OU=my-sub-ca"
```

> It is recommended to create subordinate CAs for signing leaf
> certificates. See the [official
> documentation](https://cloud.google.com/certificate-authority-service/docs/creating-certificate-authorities).

#### cert-manager

If not already running in the cluster, install cert-manager by following the [official documentation](https://cert-manager.io/docs/installation/kubernetes/).

### Installing Google CAS Issuer for cert-manager

Install the Google CAS Issuer CRDs in `config/crd`. These manifests use kustomization (hence the `-k` option).

```shell
kubectl apply -k config/crd
```

Examine the ClusterRole and ClusterRolebinding in `config/rbac/role.yaml` and
`config/rbac/role_binding.yaml`. By default, these give the default Kubernetes service
account in the cert-manager namespace all the necessary permissions. Customise these to your needs.

```shell
kubectl apply -f config/rbac/role.yaml
kubectl apply -f config/rbac/role_binding.yaml
```

#### Build and deploy the controller

To build the image, ensure you have
[kubebuilder installed](https://book.kubebuilder.io/quick-start.html#installation).

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

By default, the Google CAS Issuer controller will be deployed into the `cert-manager` namespace.

```shell
NAME                                      READY   STATUS    RESTARTS   AGE
cert-manager-6cd8cb4b7c-m8q4k             1/1     Running   0          34h
cert-manager-cainjector-685b87b86-4jvtb   1/1     Running   1          34h
cert-manager-webhook-76978fbd4c-rrx85     1/1     Running   0          34h
google-cas-issuer-687685dc46-lrjkc        1/1     Running   0          28h
```

### Setting up Google Cloud IAM

Firstly, create a Google Cloud IAM service account. This service account will be used by the CAS Issuer to access the Google Private CA APIs.

```shell
gcloud iam service-accounts create my-sa
```

Apply the appropriate IAM bindings to this account. This example permits the least privilege, to create  certificates (ie `roles/privateca.certificates.create`) from a specified suboordinate CA (`my-sub-ca`), but you can use other roles as necessary (see [Predefined Roles](https://cloud.google.com/certificate-authority-service/docs/reference/permissions-and-roles#predefined_roles) for more details).

```shell
gcloud beta privateca subordinates add-iam-policy-binding my-sub-ca --role=roles/privateca.certificateRequester --member='serviceAccount:my-sa@project-id.iam.gserviceaccount.com'
```

#### Inside GKE with workload identity

One important requirement for your GKE cluster is that it must be set up to
use the [workload
identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity). If you want to create a cluster from scratch to test the issuer, you can do:

```sh
gcloud container clusters create test --region us-east1 --num-nodes=1 --preemptible \
  --workload-pool=$(gcloud config get-value project | tr ':' '/').svc.id.goog
```

If you want to use the CAS issuer in an existing cluster, you can still
enable the "workload identity" feature with:

```sh
gcloud container clusters update CLUSTER_NAME --region=CLUSTER_REGION \
  --workload-pool="$(gcloud config get-value project | tr ':' '/').svc.id.goog"
```

Now that your cluster has the "workload identity" feature turned on, you
can create a Kubernetes service account for the CAS Issuer:

```shell
kubectl create serviceaccount -n cert-manager ksa-for-cas
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

#### Outside GKE or in an unrelated GCP project

Create a key for the service account and download it to a local JSON file.

```shell
gcloud iam service-accounts keys create project-name-keyid.json --iam-account my-sa@project-id.iam.gserviceaccount.com
```

The service account key should be stored in a Kubernetes secret in your cluster so it can be accessed by the CAS Issuer controller.

```shell
 kubectl -n cert-manager create secret generic googlesa --from-file project-name-keyid.json
```

### Configuring the Issuer

cert-manager is configured for Google CAS using either a `GoogleCASIssuer` (namespace-scoped) or a `GoogleCASClusterIssuer` (cluster-wide).

```yaml
apiVersion: cas-issuer.jetstack.io/v1alpha1
kind: GoogleCASIssuer
metadata:
  name: googlecasissuer-sample
spec:
  project: project-name
  location: europe-west1
  certificateAuthorityID: my-sub-ca
  # credentials are optional if workload identity is enabled
  credentials:
    name: "googlesa"
    key: "project-name-keyid.json"
```

```shell
kubectl apply -f googlecasissuer-sample.yaml
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
  certificateAuthorityID: my-sub-ca
  # credentials are optional if workload identity is enabled
  credentials:
    name: "googlesa"
    key: "project-name-keyid.json"
```

```shell
kubectl apply -f googlecasclusterissuer-sample.yaml
```

### Creating your first certificate

You can now create certificates as normal, but ensure the `IssuerRef` is set to the Issuer created in the previous step.

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

```shell
kubectl apply -f demo-certificate.yaml
```

In short time, the certificate will be requested and made available to the cluster.

```shell
kubectl get certificates,secret
NAME                                          READY   SECRET         AGE
certificate.cert-manager.io/bar-certificate   True    demo-cert-tls  1m

NAME                                     TYPE                                  DATA   AGE
secret/demo-cert-tls                     kubernetes.io/tls                     3      1m
```
