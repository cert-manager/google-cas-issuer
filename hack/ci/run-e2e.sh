#!/usr/bin/env bash

set -o errexit

REPO_ROOT="${REPO_ROOT:-$(dirname "${BASH_SOURCE}")/../..}"
BINDIR="${BINDIR:-${REPO_ROOT}/bin}"
IMG_REPO="${IMG_REPO:-quay.io/jetstack/cert-manager-google-cas-issuer}"
IMG_TAG="${IMG_TAG:-latest}"
E2E_LOG_DIR="${E2E_LOG_DIR:-${REPO_ROOT}/_artifacts/e2e/logs}"

export PATH="${BINDIR}:${PATH}"

cd $REPO_ROOT
KUBECONFIG=$(pwd)/kubeconfig.yaml

function export_logs_delete {
  echo "Exporting e2e test logs"
  rm -rf ${E2E_LOG_DIR}
  mkdir -p ${E2E_LOG_DIR}
  kubectl --kubeconfig $KUBECONFIG cluster-info dump --all-namespaces --output-directory ${E2E_LOG_DIR}/kubectl-cluster-info-dump --output yaml
  kind export logs --name casissuer-e2e ${E2E_LOG_DIR}
  kind delete cluster --name casissuer-e2e
}

kind version
kind create cluster --name casissuer-e2e
kind export kubeconfig --name casissuer-e2e --kubeconfig $KUBECONFIG
kind load docker-image --name casissuer-e2e $IMG_REPO:$IMG_TAG
kubectl --kubeconfig $KUBECONFIG apply -f https://github.com/jetstack/cert-manager/releases/download/v1.9.1/cert-manager.yaml
helm upgrade -i cert-manager-google-cas-issuer ./deploy/charts/google-cas-issuer -n cert-manager \
  --set image.repository=$IMG_REPO \
  --set image.tag=$IMG_TAG \
  --set image.pullPolicy=Never
timeout 5m bash -c "until kubectl --kubeconfig $KUBECONFIG --timeout=120s wait --for=condition=Ready pods --all --namespace kube-system; do sleep 1; done"
timeout 5m bash -c "until kubectl --kubeconfig $KUBECONFIG --timeout=120s wait --for=condition=Ready pods --all --namespace cert-manager; do sleep 1; done"
trap export_logs_delete EXIT
ginkgo -nodes 1 test/e2e/ -- --kubeconfig $KUBECONFIG --project jetstack-cas --location europe-west1 --capoolid issuer-e2e
