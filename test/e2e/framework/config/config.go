/*
Copyright 2024 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
