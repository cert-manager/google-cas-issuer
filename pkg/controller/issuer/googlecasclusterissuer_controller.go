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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	issuersv1alpha1 "github.com/jetstack/google-cas-issuer/api/v1alpha1"
)

// ClusterIssuers is a store for reconciled ClusterIssuers
var ClusterIssuers *sync.Map

// GoogleCASClusterIssuerReconciler reconciles a GoogleCASClusterIssuer object
type GoogleCASClusterIssuerReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=cas-issuer.jetstack.io,resources=googlecasclusterissuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cas-issuer.jetstack.io,resources=googlecasclusterissuers/status,verbs=get;update;patch
func (r *GoogleCASClusterIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("googlecasclusterissuer", req.NamespacedName)
	issuer := issuersv1alpha1.GoogleCASClusterIssuer{}

	if err := r.Client.Get(ctx, req.NamespacedName, &issuer); err != nil {
		log.Error(err, "failed to retrieve incoming ClusterIssuer resource")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return reconcile(ctx, log, r.Client, req, issuer.Spec)
}

func (r *GoogleCASClusterIssuerReconciler) setStatusCondition(ctx context.Context,
	log logr.Logger,
	issuer *issuersv1alpha1.GoogleCASClusterIssuer,
	conditionType issuersv1alpha1.GoogleCASIssuerConditionType,
	status issuersv1alpha1.ConditionStatus,
	reason string,
	message string) {
	newCondition := issuersv1alpha1.GoogleCASIssuerCondition{
		Type:    conditionType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}
	nowTime := metav1.NewTime(time.Now())
	newCondition.LastTransitionTime = &nowTime
	// Search through existing conditions
	for i, cond := range issuer.Status.Conditions {
		// Skip unrelated conditions
		if cond.Type != conditionType {
			continue
		}

		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if cond.Status == status {
			newCondition.LastTransitionTime = cond.LastTransitionTime
		} else {
			log.Info("Updating last transition time for issuer "+issuer.Name, "condition", conditionType, "old_status", cond.Status, "new_status", status, "time", nowTime.Time)
		}

		// Overwrite the existing condition
		issuer.Status.Conditions[i] = newCondition
		r.Client.Status().Update(ctx, issuer)
		return
	}
}

func (r *GoogleCASClusterIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&issuersv1alpha1.GoogleCASClusterIssuer{}).
		Complete(r)
}

func init() {
	ClusterIssuers = &sync.Map{}
}
