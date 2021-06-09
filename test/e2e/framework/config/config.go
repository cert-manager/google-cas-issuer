package config

import (
	"errors"
	"flag"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

type Config struct {
	KubeConfigPath string

	RepoRoot  string
	Namespace string

	Project  string
	Location string
	CaPoolId string
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
	fs.StringVar(&c.Project, "project", "", "GCP project name")
	fs.StringVar(&c.Location, "location", "", "GCP project location")
	fs.StringVar(&c.CaPoolId, "capoolid", "", "CA pool ID")
}

func (c *Config) Validate() error {
	var errs []error

	if c.KubeConfigPath == "" {
		errs = append(errs, errors.New("--kubeconfig not set"))
	}
	if c.Project == "" {
		errs = append(errs, errors.New("--project not set"))
	}
	if c.Location == "" {
		errs = append(errs, errors.New("--location not set"))
	}
	if c.CaPoolId == "" {
		errs = append(errs, errors.New("--capoolid not set"))
	}
	if c.Namespace == "" {
		errs = append(errs, errors.New("no namespace name set"))
	}

	return utilerrors.NewAggregate(errs)
}
