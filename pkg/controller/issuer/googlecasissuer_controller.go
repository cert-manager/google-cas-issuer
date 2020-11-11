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
	"errors"
	"github.com/jetstack/google-cas-issuer/pkg/cas"
	"github.com/spf13/viper"
	"google.golang.org/api/option"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	issuersv1alpha1 "github.com/jetstack/google-cas-issuer/api/v1alpha1"
)

// Issuers is a store for reconciled Issuers
var Issuers *sync.Map

// GoogleCASIssuerReconciler reconciles a GoogleCASIssuer object
type GoogleCASIssuerReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=cas-issuer.jetstack.io,resources=googlecasissuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cas-issuer.jetstack.io,resources=googlecasissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *GoogleCASIssuerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("googlecasissuer", req.NamespacedName)

	issuer := issuersv1alpha1.GoogleCASIssuer{}
	if err := r.Client.Get(ctx, req.NamespacedName, &issuer); err != nil {
		log.Error(err, "failed to retrieve incoming Issuer resource")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return reconcile(ctx, log, r.Client, req, issuer.Spec)
}

func (r *GoogleCASIssuerReconciler) setStatusCondition(ctx context.Context,
	log logr.Logger,
	issuer *issuersv1alpha1.GoogleCASIssuer,
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
		if err := r.Client.Status().Update(ctx, issuer); err != nil {
			log.Info("Couldn't update issuer condition:", "err", err)
		}
		return
	}
}

func (r *GoogleCASIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&issuersv1alpha1.GoogleCASIssuer{}).
		Complete(r)
}

// Reconcile is the shared reconciliation code between both the issuer and the cluster issuer.
func reconcile(ctx context.Context, log logr.Logger, client client.Client, req ctrl.Request, spec issuersv1alpha1.GoogleCASIssuerSpec) (ctrl.Result, error) {
	var secret corev1.Secret
	if len(spec.Credentials.Name) > 0 && len(spec.Credentials.Key) > 0 {
		secretNamespaceName := types.NamespacedName{
			Namespace: req.Namespace,
			Name:      spec.Credentials.Name,
		}
		if len(req.NamespacedName.Namespace) == 0 {
			secretNamespaceName.Namespace = viper.GetString("cluster-resource-namespace")
		}
		if err := client.Get(ctx, secretNamespaceName, &secret); err != nil {
			return ctrl.Result{}, err
		}
		credentials, exists := secret.Data[spec.Credentials.Key]
		if !exists {
			//r.setStatusCondition(ctx, log, &issuer, issuersv1alpha1.IssuerConditionReady, issuersv1alpha1.ConditionFalse, "SecretKeyNotFound", "Secret credentials were specified, but the Secret did not contain the specified key")
			return ctrl.Result{}, errors.New("invalid key specified")
		}
		casClient, err := cas.New(option.WithCredentialsJSON(credentials))
		if err != nil {
			//r.setStatusCondition(ctx, log, &issuer, issuersv1alpha1.IssuerConditionReady, issuersv1alpha1.ConditionFalse, "CASError", "Cas error: "+err.Error())
			return ctrl.Result{}, err
		}
		if len(req.NamespacedName.Namespace) == 0 {
			ClusterIssuers.Store(req.NamespacedName, casClient)
		} else {
			Issuers.Store(req.NamespacedName, casClient)
		}
	} else {
		casClient, err := cas.New()
		if err != nil {
			//r.setStatusCondition(ctx, log, &issuer, issuersv1alpha1.IssuerConditionReady, issuersv1alpha1.ConditionFalse, "CASError", "Cas error: "+err.Error())
			return ctrl.Result{}, err
		}
		if len(req.NamespacedName.Namespace) == 0 {
			ClusterIssuers.Store(req.NamespacedName, casClient)
		} else {
			Issuers.Store(req.NamespacedName, casClient)
		}
	}
	// r.setStatusCondition(ctx, log, &issuer, issuersv1alpha1.IssuerConditionReady, issuersv1alpha1.ConditionTrue, "Ready", "CAS Client is ready to issue certs")

	return ctrl.Result{}, nil

}

func init() {
	Issuers = &sync.Map{}
}
