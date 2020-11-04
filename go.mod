module github.com/jetstack/google-cas-issuer

go 1.13

require (
	cloud.google.com/go v0.71.0
	github.com/go-logr/logr v0.2.1-0.20200730175230-ee2de8da5be6
	github.com/go-logr/zapr v0.2.0 // indirect
	github.com/golang/protobuf v1.4.3
	github.com/google/uuid v1.1.2
	github.com/jetstack/cert-manager v1.0.4
	github.com/onsi/ginkgo v1.12.1
	github.com/onsi/gomega v1.10.1
	google.golang.org/api v0.34.0
	google.golang.org/genproto v0.0.0-20201103154000-415bd0cd5df6
	k8s.io/api v0.19.0
	k8s.io/apimachinery v0.19.0
	k8s.io/client-go v0.19.0
	sigs.k8s.io/controller-runtime v0.6.2
)
