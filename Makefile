# Image URL to use all building/pushing image targets
IMG ?= quay.io/jetstack/cert-manager-google-cas-issuer:latest

BINDIR ?= $(CURDIR)/bin
ARCH=$(shell go env GOARCH)
OS=$(shell go env GOOS)

ARTIFACTS_DIR ?= _artifacts
HELM_VERSION ?= 3.9.4
CRDS_DIR=$(CURDIR)/deploy/charts/google-cas-issuer/templates/crds/

all: google-cas-issuer

.PHONY: clean
clean: ## clean up created files
	rm -rf $(BINDIR) $(ARTIFACTS_DIR)

# Run tests
test: generate fmt vet helm-docs manifests
	go test ./api/... ./pkg/... ./cmd/... -coverprofile cover.out

.PHONY: e2e
e2e: depend docker-build
	./hack/ci/run-e2e.sh

# Build google-cas-issuer binary
google-cas-issuer: generate fmt vet
	go build -o bin/google-cas-issuer main.go

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	go run ./main.go --zap-devel=true

# Generate CRDs
manifests: depend
	$(CONTROLLER_GEN) crd schemapatch:manifests=$(CRDS_DIR) output:dir=$(CRDS_DIR) paths=./api/...

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

.PHONY: helm-docs
helm-docs: $(BINDIR)/helm-docs # verify helm-docs
	./hack/verify-helm-docs.sh

# Generate code
generate: depend
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Build the docker image
docker-build: test
	docker build . -t ${IMG}

# Push the docker image
docker-push:
	docker push ${IMG}

.PHONY: depend
depend: $(BINDIR) $(BINDIR)/kind $(BINDIR)/helm $(BINDIR)/kubectl $(BINDIR)/ginkgo $(BINDIR)/controller-gen $(BINDIR)/helm-docs

$(BINDIR):
	mkdir -p ./bin

$(BINDIR)/controller-gen:
	cd hack/tools && go build -o $@ sigs.k8s.io/controller-tools/cmd/controller-gen
CONTROLLER_GEN=$(BINDIR)/controller-gen

$(BINDIR)/kind:
	cd hack/tools && go build -o $@ sigs.k8s.io/kind
KIND=$(BINDIR)/kind

$(BINDIR)/ginkgo:
	cd hack/tools && go build -o $@ github.com/onsi/ginkgo/v2/ginkgo
GINKGO=$(BINDIR)/ginkgo

# find or download kubectl
$(BINDIR)/kubectl:
	curl -o $@ -LO "https://storage.googleapis.com/kubernetes-release/release/$(shell curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/$(OS)/$(ARCH)/kubectl"
	chmod +x $@
KUBECTL=$(BINDIR)/kubectl

$(BINDIR)/helm:
	curl -o $(BINDIR)/helm.tar.gz -LO "https://get.helm.sh/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz"
	tar -C $(BINDIR) -xzf $(BINDIR)/helm.tar.gz
	cp $(BINDIR)/$(OS)-$(ARCH)/helm $(BINDIR)/helm
	rm -r $(BINDIR)/$(OS)-$(ARCH) $(BINDIR)/helm.tar.gz
HELM=$(BINDIR)/helm

$(BINDIR)/helm-docs:
		cd hack/tools && go build -o $(BINDIR)/helm-docs github.com/norwoodj/helm-docs/cmd/helm-docs
