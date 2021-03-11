module github.com/jetstack/google-cas-issuer

go 1.13

require (
	cloud.google.com/go v0.71.0
	github.com/go-logr/logr v0.3.0
	github.com/golang/protobuf v1.4.3
	github.com/google/uuid v1.1.2
	github.com/jetstack/cert-manager v1.0.4
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1 // indirect
	google.golang.org/api v0.34.0
	google.golang.org/genproto v0.0.0-20201110150050-8816d57aaa9a
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1
	sigs.k8s.io/controller-runtime v0.8.0
)
