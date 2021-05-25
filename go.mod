module github.com/jetstack/google-cas-issuer

go 1.16

require (
	cloud.google.com/go v0.82.0
	github.com/go-logr/logr v0.3.0
	github.com/golang/protobuf v1.5.2
	github.com/google/uuid v1.1.2
	github.com/jetstack/cert-manager v1.3.1
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	google.golang.org/api v0.46.0
	google.golang.org/genproto v0.0.0-20210520160233-290a1ae68a05
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/cli-runtime v0.20.1
	k8s.io/client-go v0.20.1
	k8s.io/klog/v2 v2.4.0
	sigs.k8s.io/controller-runtime v0.8.0
)
