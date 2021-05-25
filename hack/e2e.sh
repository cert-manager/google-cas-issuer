#!/usr/bin/env bash
set -xe

export KIND_CLUSTER_NAME=kind-cas-issuer
kind create cluster
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.2.0/cert-manager.yaml
kubectl -n cert-manager create secret generic googlesa --from-file=/Users/jakexks/Downloads/jetstack-cas-b2a950e42388.json
kubectl create secret generic googlesa --from-file=/Users/jakexks/Downloads/jetstack-cas-b2a950e42388.json
kubectl --timeout=120s wait --for=condition=Ready pods --all --namespace kube-system
kubectl --timeout=120s wait --for=condition=Ready pods --all --namespace cert-manager

make google-cas-issuer
export E2E_DOCKER_TAG=e2etest
docker build -t quay.io/jetstack/google-cas-issuer:$E2E_DOCKER_TAG .
kind load docker-image quay.io/jetstack/google-cas-issuer:$E2E_DOCKER_TAG

kustomize build config/crd | kubectl apply -f -

cat <<EOF | kubectl apply -f -
apiVersion: cas-issuer.jetstack.io/v1alpha1
kind: GoogleCASClusterIssuer
metadata:
  name: e2etest-clusterissuer
spec:
  project: jetstack-cas
  location: europe-west1
  certificateAuthorityID: demo-root
  credentials:
    name: "googlesa"
    key: "jetstack-cas-b2a950e42388.json"
EOF

cat <<EOF | kubectl apply -f -
apiVersion: cas-issuer.jetstack.io/v1alpha1
kind: GoogleCASIssuer
metadata:
  name: e2etest-issuer
spec:
  project: jetstack-cas
  location: europe-west1
  certificateAuthorityID: demo-root
  credentials:
    name: "googlesa"
    key: "jetstack-cas-b2a950e42388.json"
EOF

cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: e2etest-certificate
  namespace: default
spec:
  # The secret name to store the signed certificate
  secretName: e2etest-tls
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
    name: e2etest-clusterissuer
EOF

cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: e2etest-certificate-issuer
  namespace: default
spec:
  # The secret name to store the signed certificate
  secretName: e2etest-issuer-tls
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
    kind: GoogleCASIssuer
    name: e2etest-issuer
EOF

#make run

make manifests
pushd config/manager
kustomize edit set image controller=quay.io/jetstack/google-cas-issuer:$E2E_DOCKER_TAG
popd
kustomize build config/default | tee deploy/google-cas-issuer.yaml
