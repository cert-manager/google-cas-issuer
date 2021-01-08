/*
Copyright 2020 the cert-manager authors.

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

package issuer

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/jetstack/google-cas-issuer/pkg/cas"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"

	issuersv1alpha1 "github.com/jetstack/google-cas-issuer/api/v1alpha1"
)

// GoogleCASIssuerReconciler reconciles a GoogleCASIssuer object
type GoogleCASIssuerReconciler struct {
	// GoogleCASIssuer or GoogleCASClusterIssuer
	Kind string

	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=cas-issuer.jetstack.io,resources=googlecasissuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cas-issuer.jetstack.io,resources=googlecasissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
func (r *GoogleCASIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := r.Log.WithValues(r.Kind, req.NamespacedName)
	issuer, err := r.getIssuer()
	if err != nil {
		log.Error(err, "invalid issuer type seen - ignoring")
		return ctrl.Result{}, nil
	}

	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			log.Error(err, "failed to retrieve incoming Issuer resource")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	spec, status, err := getIssuerSpecStatus(issuer)
	if err != nil {
		log.Error(err, "issuer is of unexpected type, ignoring")
		return ctrl.Result{}, nil
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			setReadyCondition(status, issuersv1alpha1.ConditionFalse, "issuer failed to reconcile", err.Error())
		}
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			result = ctrl.Result{}
		}
	}()

	ns := req.NamespacedName.Namespace
	if len(ns) == 0 {
		ns = viper.GetString("cluster-resource-namespace")
	}

	_, err = cas.NewSigner(ctx, spec, r.Client, ns)

	if err != nil {
		log.Info("Issuer is misconfigured", "info", err.Error())
		setReadyCondition(status, issuersv1alpha1.ConditionFalse, "issuer is misconfigured", err.Error())
		return ctrl.Result{RequeueAfter: 10*time.Second}, nil
	}

	log.Info("reconciled issuer", "kind", issuer.GetObjectKind())
	setReadyCondition(status, issuersv1alpha1.ConditionTrue, "Successfully constructed CAS client", "")
	return ctrl.Result{}, nil
}

func (r *GoogleCASIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuer, err := r.getIssuer()
	if err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(issuer).
		Complete(r)
}

// convert a k8s.io/apimachinery/pkg/runtime.Object into a sigs.k8s.io/controller-runtime/pkg/client.Object
func (r *GoogleCASIssuerReconciler) getIssuer() (client.Object, error) {
	issuer, err := r.Scheme.New(issuersv1alpha1.GroupVersion.WithKind(r.Kind))
	if err != nil {
		return nil, err
	}
	switch t := issuer.(type) {
	case *issuersv1alpha1.GoogleCASIssuer:
		return t, nil
	case *issuersv1alpha1.GoogleCASClusterIssuer:
		return t, nil
	default:
		return nil, fmt.Errorf("unsupported kind %s", r.Kind)
	}
}

func getIssuerSpecStatus(object client.Object) (*issuersv1alpha1.GoogleCASIssuerSpec, *issuersv1alpha1.GoogleCASIssuerStatus, error) {
	switch t := object.(type) {
	case *issuersv1alpha1.GoogleCASIssuer:
		return &t.Spec, &t.Status, nil
	case *issuersv1alpha1.GoogleCASClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("unexpected type %T", t)
	}
}

func setReadyCondition(status *issuersv1alpha1.GoogleCASIssuerStatus, conditionStatus issuersv1alpha1.ConditionStatus, reason, message string) {
	var ready *issuersv1alpha1.GoogleCASIssuerCondition
	for _, c := range status.Conditions {
		if c.Type == issuersv1alpha1.IssuerConditionReady {
			ready = &c
			break
		}
	}
	if ready == nil {
		ready = &issuersv1alpha1.GoogleCASIssuerCondition{Type: issuersv1alpha1.IssuerConditionReady}
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions{
		if c.Type == issuersv1alpha1.IssuerConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}