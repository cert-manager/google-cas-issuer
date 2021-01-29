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

package certificaterequest

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	cmutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/google-cas-issuer/pkg/cas"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	casapi "github.com/jetstack/google-cas-issuer/api/v1alpha1"
)

// CertificateRequestReconciler reconciles CRs
type CertificateRequestReconciler struct {
	client.Client
	Log logr.Logger
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;create;update
func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := r.Log.WithValues("certificaterequest", req.NamespacedName)

	// Fetch the CertificateRequest resource being reconciled.
	// Just ignore the request if the certificate request has been deleted.
	var certificateRequest cmapi.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			log.Info("Certificate Request not found, ignoring", "cr", req.NamespacedName)
		}
		return ctrl.Result{}, err
	}

	// Check the CertificateRequest's issuerRef and if it does not match the api
	// group name, log a message at a debug level and stop processing.
	if certificateRequest.Spec.IssuerRef.Group != casapi.GroupVersion.Group {
		log.Info("CR is for a different Issuer", "group", certificateRequest.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// Ignore already Ready CRs
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		log.Info("CertificateRequest is Ready, Ignoring.", "certificaterequest", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// We now have a CertificateRequest that belongs to us so we are responsible
	// for updating its Ready condition.
	setReadyCondition := func(status cmmeta.ConditionStatus, reason, message string) {
		cmutil.SetCertificateRequestCondition(
			&certificateRequest,
			cmapi.CertificateRequestConditionReady,
			status,
			reason,
			message,
		)
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, err.Error())
		}
		if updateErr := r.Status().Update(ctx, &certificateRequest); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	// Add a Ready condition if one does not already exist
	if ready := cmutil.GetCertificateRequestCondition(&certificateRequest, cmapi.CertificateRequestConditionReady); ready == nil {
		log.Info("Initialising Ready condition")
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Initialising")
		// re-reconcile
		return ctrl.Result{}, nil
	}

	// Get (cluster)issuer
	issuerGroupVersionKind := casapi.GroupVersion.WithKind(certificateRequest.Spec.IssuerRef.Kind)
	issuerGeneric, err := r.Scheme().New(issuerGroupVersionKind)
	var spec *casapi.GoogleCASIssuerSpec
	var ns string
	if err != nil {
		log.Error(err, "unknown issuer kind", "kind", certificateRequest.Spec.IssuerRef.Kind)
		// Status should update here
		// send an event here
		return ctrl.Result{}, nil
	}
	switch t := issuerGeneric.(type) {
	case *casapi.GoogleCASIssuer:
		err := r.Client.Get(ctx, types.NamespacedName{
			Namespace: req.NamespacedName.Namespace,
			Name:      certificateRequest.Spec.IssuerRef.Name,
		}, t)
		if err != nil {
			if client.IgnoreNotFound(err) == nil {
				log.Info("ignoring not found")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		spec = &t.Spec
		ns = req.NamespacedName.Namespace
	case *casapi.GoogleCASClusterIssuer:
		err := r.Client.Get(ctx, types.NamespacedName{
			Name: certificateRequest.Spec.IssuerRef.Name,
		}, t)
		if err != nil {
			if client.IgnoreNotFound(err) == nil {
				log.Info("ignoring not found")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		spec = &t.Spec
		ns = viper.GetString("cluster-resource-namespace")
	default:
		log.Error(err, "unknown issuer type", "object", t)
		// TODO: send event 😁
		return ctrl.Result{}, nil
	}
	signer, err := cas.NewSigner(ctx, spec, r.Client, ns)
	if err != nil {
		log.Error(err, "couldn't construct signer for certificate", "cr", req.NamespacedName)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Sign certificate
	cert, ca, err := signer.Sign(certificateRequest.Spec.Request, certificateRequest.Spec.Duration.Duration)
	if err != nil {
		return ctrl.Result{}, err
	}
	certificateRequest.Status.CA = ca
	certificateRequest.Status.Certificate = cert
	setReadyCondition(cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Certificate issued")
	return ctrl.Result{}, nil
}

// SetupWithManager initializes the CertificateRequest controller into the
// controller runtime.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
