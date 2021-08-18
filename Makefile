
# Image URL to use all building/pushing image targets
IMG ?= quay.io/jetstack/cert-manager-google-cas-issuer:latest
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:trivialVersions=true"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)

all: google-cas-issuer

# Run tests
test: generate fmt vet manifests
	go test ./api/... ./pkg/... ./cmd/... -coverprofile cover.out

.PHONY: e2e
e2e: kind kustomize ginkgo kubectl docker-build
	$(KIND) version
	$(KIND) create cluster --name casissuer-e2e
	$(KIND) export kubeconfig --name casissuer-e2e --kubeconfig kubeconfig.yaml
	$(KIND) load docker-image --name casissuer-e2e ${IMG}
	$(KUBECTL) --kubeconfig kubeconfig.yaml apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.1/cert-manager.yaml
	$(KUSTOMIZE) build config/crd | $(KUBECTL) --kubeconfig kubeconfig.yaml apply -f -
	cd config/manager; $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | $(KUBECTL) --kubeconfig kubeconfig.yaml apply -f -
	timeout 5m bash -c 'until $(KUBECTL) --kubeconfig kubeconfig.yaml --timeout=120s wait --for=condition=Ready pods --all --namespace kube-system; do sleep 1; done'
	timeout 5m bash -c 'until $(KUBECTL) --kubeconfig kubeconfig.yaml --timeout=120s wait --for=condition=Ready pods --all --namespace cert-manager; do sleep 1; done'
	$(GINKGO) -nodes 1 test/e2e/ -- --kubeconfig $$(pwd)/kubeconfig.yaml --project jetstack-cas --location europe-west1 --capoolid issuer-e2e
	$(KIND) delete cluster --name casissuer-e2e

# Build google-cas-issuer binary
google-cas-issuer: generate fmt vet
	go build -o bin/google-cas-issuer main.go

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	go run ./main.go --zap-devel=true

# Install CRDs into a cluster
install: manifests kustomize
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests kustomize
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests kustomize
	cd config/manager && kustomize edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=google-cas-issuer-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Generate code
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Build the docker image
docker-build: test
	docker build . -t ${IMG}

# Push the docker image
docker-push:
	docker push ${IMG}

# find or download controller-gen
controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
	set -e ;\
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.5.0 ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif

# find or download kustomize
kustomize:
ifeq (, $(shell which kustomize))
	@{ \
	set -e ;\
	TEMPDIR=$(mktemp -d);\
	cd $$TEMPDIR ;\
	GO111MODULE=on go get sigs.k8s.io/kustomize/kustomize/v3 ;\
	}
KUSTOMIZE=$(GOBIN)/kustomize
else
KUSTOMIZE=$(shell which kustomize)
endif

# find or download kind
kind:
ifeq (, $(shell which kind))
	@{ \
	set -e ;\
	TEMPDIR=$(mktemp -d);\
	cd $$TEMPDIR ;\
	GO111MODULE=on go get sigs.k8s.io/kind@v0.11.1 ;\
	}
KIND=$(GOBIN)/kind
else
KIND=$(shell which kind)
endif

# find or download ginkgo
ginkgo:
ifeq (, $(shell which ginkgo))
	@{ \
	set -e ;\
	TEMPDIR=$(mktemp -d);\
	cd $$TEMPDIR ;\
	GO111MODULE=on go get github.com/onsi/ginkgo/ginkgo ;\
	}
GINKGO=$(GOBIN)/ginkgo
else
GINKGO=$(shell which ginkgo)
endif

# find or download kubectl
kubectl:
ifeq (, $(shell which kubectl))
	@{ \
	set -e ;\
	curl -LO "https://dl.k8s.io/release/$$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/$(GOOS)/$(GOARCH)/kubectl" ;\
	chmod a+x kubectl ;\
	mv kubectl $(GOBIN)/kubectl ;\
	}
KUBECTL=$(GOBIN)/kubectl
else
KUBECTL=$(shell which kubectl)
endif

