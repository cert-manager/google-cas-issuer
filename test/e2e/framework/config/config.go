package config

import (
	"errors"
	"flag"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

type Config struct {
	KubeConfigPath string

	RepoRoot string
}

var (
	sharedConfig = &Config{}
)

func SetConfig(config *Config) {
	sharedConfig = config
}

func GetConfig() *Config {
	return sharedConfig
}

func (c *Config) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.KubeConfigPath, "kubeconfig", "", "path to Kubeconfig")
}

func (c *Config) Validate() error {
	var errs []error

	if c.KubeConfigPath == "" {
		errs = append(errs, errors.New("--kubeconfig not set"))
	}

	return utilerrors.NewAggregate(errs)
}
