# Image URL to use all building/pushing image targets
IMG ?= quay.io/jetstack/cert-manager-google-cas-issuer:latest
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:trivialVersions=true"

BINDIR ?= $(CURDIR)/bin

GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)

all: google-cas-issuer

.PHONY: clean
clean: ## clean up created files
	rm -rf $(BINDIR) \

# Run tests
test: generate fmt vet manifests
	go test ./api/... ./pkg/... ./cmd/... -coverprofile cover.out

.PHONY: e2e
e2e: $(BINDIR)/kind $(BINDIR)/kustomize $(BINDIR)/ginkgo $(BINDIR)/kubectl docker-build
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
install: manifests $(BINDIR)/kustomize
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests $(BINDIR)/kustomize
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests $(BINDIR)/kustomize
	cd config/manager && $(BINDIR)/kustomize edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests: $(BINDIR)/controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=google-cas-issuer-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Generate code
generate: $(BINDIR)/controller-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Build the docker image
docker-build: test
	docker build . -t ${IMG}

# Push the docker image
docker-push:
	docker push ${IMG}

$(BINDIR):
	mkdir -p ./bin

$(BINDIR)/controller-gen: $(BINDIR)
	cd hack/tools && go build -o $@ sigs.k8s.io/controller-tools/cmd/controller-gen
CONTROLLER_GEN=$(BINDIR)/controller-gen

$(BINDIR)/kustomize: $(BINDIR)
	cd hack/tools && go build -o $@ sigs.k8s.io/kustomize/kustomize/v3
KUSTOMIZE=$(BINDIR)/kustomize

$(BINDIR)/kind: $(BINDIR)
	cd hack/tools && go build -o $@ sigs.k8s.io/kind
KIND=$(BINDIR)/kind

$(BINDIR)/ginkgo: $(BINDIR)
	cd hack/tools && go build -o $@ github.com/onsi/ginkgo/v2/ginkgo
GINKGO=$(BINDIR)/ginkgo

# find or download kubectl
$(BINDIR)/kubectl: $(BINDIR)
	curl -o $@ -LO "https://storage.googleapis.com/kubernetes-release/release/$(shell curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/$(OS)/$(ARCH)/kubectl"
	chmod +x $@
KUBECTL=$(BINDIR)/kubectl
