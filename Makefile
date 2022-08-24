# Image URL to use all building/pushing image targets
IMG ?= quay.io/jetstack/cert-manager-google-cas-issuer:latest

BINDIR ?= $(CURDIR)/bin
ARCH=$(shell go env GOARCH)
OS=$(shell go env GOOS)

ARTIFACTS_DIR ?= _artifacts

all: google-cas-issuer

.PHONY: clean
clean: ## clean up created files
	rm -rf $(BINDIR) $(ARTIFACTS_DIR)

# Run tests
test: generate fmt vet manifests
	go test ./api/... ./pkg/... ./cmd/... -coverprofile cover.out

.PHONY: e2e
e2e: $(BINDIR)/kind $(BINDIR)/kustomize $(BINDIR)/ginkgo $(BINDIR)/kubectl docker-build
	./hack/ci/run-e2e.sh

# Build google-cas-issuer binary
google-cas-issuer: generate fmt vet
	go build -o bin/google-cas-issuer main.go

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	go run ./main.go --zap-devel=true

# Install CRDs into a cluster
install: manifests $(BINDIR)/kustomize
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests $(BINDIR)/kustomize
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete -f -

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests $(BINDIR)/kustomize
	cd config/manager && $(BINDIR)/kustomize edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests: $(BINDIR)/controller-gen
	$(CONTROLLER_GEN) crd rbac:roleName=google-cas-issuer-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

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
	cd hack/tools && go build -o $@ github.com/onsi/ginkgo/ginkgo
GINKGO=$(BINDIR)/ginkgo

# find or download kubectl
$(BINDIR)/kubectl: $(BINDIR)
	curl -o $@ -LO "https://storage.googleapis.com/kubernetes-release/release/$(shell curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/$(OS)/$(ARCH)/kubectl"
	chmod +x $@
KUBECTL=$(BINDIR)/kubectl
