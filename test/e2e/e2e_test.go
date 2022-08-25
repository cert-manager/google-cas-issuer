package e2e

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/reporters"
	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"

	_ "github.com/jetstack/google-cas-issuer/test/e2e/suite"
)

func init() {
	wait.ForeverTestTimeout = time.Second * 60
}

func TestE2E(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)

	junitPath := "../../_artifacts"
	if path := os.Getenv("ARTIFACTS"); path != "" {
		junitPath = path
	}

	junitReporter := reporters.NewJUnitReporter(filepath.Join(
		junitPath,
		"junit-go-e2e.xml",
	))
	ginkgo.RunSpecsWithDefaultAndCustomReporters(t, "jetstack google-cas-issuer e2e suite", []ginkgo.Reporter{junitReporter})
}
