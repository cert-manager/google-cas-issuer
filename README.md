# Google Certificate Authority Service Issuer for cert-manager

This repository contains an [external Issuer](https://cert-manager.io/docs/contributing/external-issuers/)
for cert-manager that issues certificates using [Google Cloud
Certificate Authority Service (CAS)](https://cloud.google.com/certificate-authority-service/), using managed private CAs to issue certificates.

## Getting started

### Prerequisites

#### CAS-enabled GCP project

Enable the Certificate Authority API (`privateca.googleapis.com`) in your GCP project by following the
[official documentation](https://cloud.google.com/certificate-authority-service/docs/quickstart).

#### CAS-managed Certificate Authorities

You can create a ca pool containing a certificate authority in your current Google project with:

```shell
gcloud privateca pools create my-pool --location us-east1
gcloud privateca roots create my-ca --pool my-pool --key-algorithm "ec-p384-sha384" --subject="CN=my-root,O=my-ca,OU=my-ou" --max-chain-length=2 --location us-east1
```

You should also enable the root CA you just created when prompted by `gcloud`.

> It is recommended to create subordinate CAs for signing leaf
> certificates. See the [official
> documentation](https://cloud.google.com/certificate-authority-service/docs/creating-certificate-authorities).

#### cert-manager

If not already running in the cluster, install cert-manager by following the [official documentation](https://cert-manager.io/docs/installation/kubernetes/).

### Installing Google CAS Issuer for cert-manager

```shell
helm repo add jetstack https://charts.jetstack.io --force-update
helm upgrade -i cert-manager-google-cas-issuer jetstack/cert-manager-google-cas-issuer -n cert-manager --wait
```

Or alternatively, assuming that you have installed cert-manager in the `cert-manager` namespace, you can use a single kubectl
command to install Google CAS Issuer.
Visit the [GitHub releases](https://github.com/jetstack/google-cas-issuer/releases), select the latest release
and copy the command, e.g.

```shell
kubectl apply -f https://github.com/jetstack/google-cas-issuer/releases/download/v0.6.1/google-cas-issuer-v0.6.1.yaml
```

You can then skip to the [Setting up Google Cloud IAM](#setting-up-google-cloud-iam) section.

##### Build and push the controller image

**Note**: you can skip this step if using the public images at [quay.io](https://quay.io/repository/jetstack/cert-manager-google-cas-issuer?tag=latest&tab=tags).

Build the docker image:

```shell
make docker-build
```

Push the docker image or load it into kind for testing

```shell
make docker-push || kind load docker-image quay.io/jetstack/cert-manager-google-cas-issuer:latest
```

#### Deploy the controller

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
      serviceAccountName: ksa-google-cas-issuer
      containers:
      # update the image to your registry if you built and pushed your own image.
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

Firstly, create a Google Cloud IAM service account. This service account will be used by the CAS Issuer to access the Google Cloud CAS APIs.

```shell
gcloud iam service-accounts create sa-google-cas-issuer
```

Apply the appropriate IAM bindings to this account. This example permits the least privilege, to create certificates (ie `roles/privateca.certificates.create`) from a specified CA pool (`my-pool`), but you can use other roles as necessary (see [Predefined Roles](https://cloud.google.com/certificate-authority-service/docs/reference/permissions-and-roles#predefined_roles) for more details).

```shell
gcloud privateca pools add-iam-policy-binding my-pool --role=roles/privateca.certificateRequester --member="serviceAccount:sa-google-cas-issuer@$(gcloud config get-value project | tr ':' '/').iam.gserviceaccount.com" --location=us-east1
```

#### Inside GKE with workload identity

[Workload identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) lets you bind a
Kubernetes service account to a Google Cloud service account. In order to take advantage of this, your
GKE cluster must be set up to use it. If you want to create a cluster from scratch to test the issuer,
you can enable it like so:

```sh
gcloud container clusters create test --region us-east1 --num-nodes=1 --preemptible \
  --workload-pool=$(gcloud config get-value project | tr ':' '/').svc.id.goog
```

If you want to use the CAS issuer in an existing cluster, you can still
enable the workload identity feature with:

```sh
gcloud container clusters update CLUSTER_NAME --region=CLUSTER_REGION \
  --workload-pool="$(gcloud config get-value project | tr ':' '/').svc.id.goog"
```

Bind the Kubernetes service account (`ksa-google-cas-issuer`) to the Google Cloud service account:

```shell
export PROJECT=$(gcloud config get-value project | tr ':' '/')

gcloud iam service-accounts add-iam-policy-binding \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:$PROJECT.svc.id.goog[cert-manager/ksa-google-cas-issuer]" \
  sa-google-cas-issuer@${PROJECT:?PROJECT is not set}.iam.gserviceaccount.com

kubectl annotate serviceaccount \
  --namespace cert-manager \
  ksa-google-cas-issuer \
  iam.gke.io/gcp-service-account=sa-google-cas-issuer@${PROJECT:?PROJECT is not set}.iam.gserviceaccount.com \
  --overwrite=true
```

#### Outside GKE or in an unrelated GCP project

Create a key for the service account and download it to a local JSON file.

```shell
gcloud iam service-accounts keys create $(gcloud config get-value project | tr ':' '/')-key.json \
  --iam-account sa-google-cas-issuer@$(gcloud config get-value project | tr ':' '/').iam.gserviceaccount.com
```

The service account key should be stored in a Kubernetes secret in your cluster so it can be accessed by the CAS Issuer controller.

```shell
 kubectl -n cert-manager create secret generic googlesa --from-file $(gcloud config get-value project | tr ':' '/')-key.json
```

### Configuring the Issuer

cert-manager is configured for Google CAS using either a `GoogleCASIssuer` (namespace-scoped) or a `GoogleCASClusterIssuer` (cluster-wide).

Inspect the sample configurations below and update the PROJECT_ID as appropriate. Credentials can be omitted if you have configured the CAS issuer controller with Workload Identity.

```yaml
# googlecasissuer-sample.yaml
apiVersion: cas-issuer.jetstack.io/v1beta1
kind: GoogleCASIssuer
metadata:
  name: googlecasissuer-sample
spec:
  project: $PROJECT_ID
  location: us-east1
  caPoolId: my-pool
  # credentials are optional if workload identity is enabled
  credentials:
    name: "googlesa"
    key: "$PROJECT_ID-key.json"
```

```shell
kubectl apply -f googlecasissuer-sample.yaml
```

or

```yaml
# googlecasclusterissuer-sample.yaml
apiVersion: cas-issuer.jetstack.io/v1beta1
kind: GoogleCASClusterIssuer
metadata:
  name: googlecasclusterissuer-sample
spec:
  project: $PROJECT_ID
  location: us-east1
  caPoolId: my-pool
  # credentials are optional if workload identity is enabled
  credentials:
    name: "googlesa"
    key: "$PROJECT_ID-key.json"
```

```shell
kubectl apply -f googlecasclusterissuer-sample.yaml
```

### Creating your first certificate

You can now create certificates as normal, but ensure the `IssuerRef` is set to the `GoogleCASIssuer` or `GoogleCASClusterIssuer` created in the previous step.

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
    kind: GoogleCASClusterIssuer # or GoogleCASIssuer
    name: googlecasclusterissuer-sample # or googlecasissuer-sample
```

```shell
kubectl apply -f demo-certificate.yaml
```

In short time, the certificate will be requested and made available to the cluster.

```shell
kubectl get certificates,secret
NAME                                           READY   SECRET         AGE
certificate.cert-manager.io/demo-certificate   True    demo-cert-tls  1m

NAME                                     TYPE                                  DATA   AGE
secret/demo-cert-tls                     kubernetes.io/tls                     3      1m
```

## Continuous Integration

This project uses GitHub Actions to run continuous integration tests.
There are two required test workflows:
- `run_unit_tests` - this runs automatically on every pull request
- `run_e2e_tests` - this runs on a pull request when the `ok-to-test` label is added  
**⚠️ IMPORTANT: A maintainer must add this label manually after verifying that the commits in your PR are non-malicious. Ping a maintainer when your PR is ready. This label has to be re-added every time a change is made in the PR.**
