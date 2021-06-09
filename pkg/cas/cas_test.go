/*
Copyright 2021 Jetstack Ltd.

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

package cas

import (
	"context"
	"fmt"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/jetstack/google-cas-issuer/api/v1beta1"
)

func TestNewSigner(t *testing.T) {
	spec := &v1beta1.GoogleCASIssuerSpec{
		CaPoolId: "test-pool",
		Project:  "test-project",
		Location: "test-location",
	}
	ctx := context.Background()
	namespace := "test"
	client := fake.NewFakeClient()
	res, err := newSignerNoSelftest(ctx, spec, client, namespace)
	if err != nil {
		t.Errorf("NewSigner returned an error: %s", err.Error())
	}
	if got, want := res.parent, fmt.Sprintf("projects/%s/locations/%s/caPools/%s", spec.Project, spec.Location, spec.CaPoolId); got != want {
		t.Errorf("Wrong parent: %s != %s", got, want)
	}
	if got, want := res.namespace, namespace; got != want {
		t.Errorf("Wrong namespace: %s != %s", got, want)
	}
}

func TestNewSignerMissingPoolId(t *testing.T) {
	spec := &v1beta1.GoogleCASIssuerSpec{
		CaPoolId: "",
	}
	ctx := context.Background()
	namespace := "test"
	client := fake.NewFakeClient()
	_, err := newSignerNoSelftest(ctx, spec, client, namespace)
	if err == nil {
		t.Error("NewSigner didn't return an error")
	}
	if got, want := err.Error(), "must specify a CaPoolId"; got != want {
		t.Errorf("Wrong error: %s != %s", got, want)
	}
}
