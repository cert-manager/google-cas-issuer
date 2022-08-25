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

package certificaterequest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/client-go/tools/record"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	"github.com/jetstack/google-cas-issuer/pkg/cas"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	casapi "github.com/jetstack/google-cas-issuer/api/v1"
)

const (
	eventTypeWarning = "Warning"
	eventTypeNormal  = "Normal"

	reasonInvalidIssuer  = "InvalidIssuer"
	reasonSignerNotReady = "SignerNotReady"
	reasonCRInvalid      = "CRInvalid"
	reasonCertIssued     = "CertificateIssued"
	reasonCRNotApproved  = "CRNotApproved"
)

// CertificateRequestReconciler reconciles CRs
type CertificateRequestReconciler struct {
	client.Client
	Log      logr.Logger
	Recorder record.EventRecorder
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

	// Ignore CRs that have reached a terminal state
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		log.Info("CertificateRequest is Ready, ignoring.", "cr", req.NamespacedName)
		return ctrl.Result{}, nil
	}
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}) {
		log.Info("CertificateRequest has been denied, ignoring.", "cr", req.NamespacedName)
		return ctrl.Result{}, nil
	}
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		log.Info("CertificateRequest has failed, ignoring.", "cr", req.NamespacedName)
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
		// The certificateRequest may have been deleted in the meantime, ignore any not found errors
		if updateErr := client.IgnoreNotFound(r.Status().Update(ctx, &certificateRequest)); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	// Explicitly fail if the certificate request has been denied
	if cmutil.CertificateRequestIsDenied(&certificateRequest) {
		msg := "certificate request has been denied, not signing"
		log.Info(msg, "cr", req.NamespacedName)
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, msg)
		return ctrl.Result{}, nil
	}

	// From cert-manager v1.3 onwards, CertificateRequests must be approved before they are signed.
	if !viper.GetBool("disable-approval-check") {
		log.Info("Checking whether CR has been approved", "cr", req.NamespacedName)
		if !cmutil.CertificateRequestIsApproved(&certificateRequest) {
			msg := "certificate request is not approved yet"
			log.Info(msg, "cr", req.NamespacedName)
			r.Recorder.Event(&certificateRequest, eventTypeWarning, reasonCRNotApproved, msg)
			return ctrl.Result{}, nil
		}
	}

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
		msg := "The issuer kind " + certificateRequest.Spec.IssuerRef.Kind + " is invalid"
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, msg)
		r.Recorder.Event(&certificateRequest, eventTypeWarning, reasonInvalidIssuer, msg)
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
				log.Info("Issuer not found", "Issuer", certificateRequest.Spec.IssuerRef.Name, "namespace", req.NamespacedName.Namespace)
				msg := "The issuer " + certificateRequest.Spec.IssuerRef.Name + " was not found"
				setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, msg)
				r.Recorder.Event(&certificateRequest, eventTypeWarning, reasonInvalidIssuer, msg)
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
				log.Info("ClusterIssuer not found", "CLusterIssuer", certificateRequest.Spec.IssuerRef.Name)
				msg := "The ClusterIssuer " + certificateRequest.Spec.IssuerRef.Name + " was not found"
				setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, msg)
				r.Recorder.Event(&certificateRequest, eventTypeWarning, reasonInvalidIssuer, msg)
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		spec = &t.Spec
		ns = viper.GetString("cluster-resource-namespace")
	default:
		log.Error(err, "unknown issuer type", "object", t)
		msg := "Unknown issuer type"
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, msg)
		r.Recorder.Event(&certificateRequest, eventTypeWarning, reasonInvalidIssuer, msg)
		return ctrl.Result{}, nil
	}
	signer, err := cas.NewSigner(ctx, spec, r.Client, ns)
	if err != nil {
		log.Error(err, "couldn't construct signer for certificate", "cr", req.NamespacedName)
		msg := "Couldn't construct signer, check if CA pool " + spec.CaPoolId + "is ready"
		r.Recorder.Event(&certificateRequest, eventTypeWarning, reasonSignerNotReady, msg)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Check for obvious errors, e.g. missing duration, malformed certificate request
	if err := sanitiseCertificateRequestSpec(&certificateRequest.Spec); err != nil {
		log.Error(err, "certificate request has issues", "cr", req.NamespacedName)
		msg := "certificate request has issues: " + err.Error()
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, msg)
		r.Recorder.Event(&certificateRequest, eventTypeWarning, reasonCRInvalid, msg)
		return ctrl.Result{}, nil
	}

	// Sign certificate
	cert, ca, err := signer.Sign(certificateRequest.Spec.Request, certificateRequest.Spec.Duration.Duration)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to sign certificate request: %w", err)
	}
	certificateRequest.Status.CA = ca
	certificateRequest.Status.Certificate = cert
	msg := "Certificate Issued"
	setReadyCondition(cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, msg)
	r.Recorder.Event(&certificateRequest, eventTypeNormal, reasonCertIssued, msg)
	return ctrl.Result{}, nil
}

// SetupWithManager initializes the CertificateRequest controller into the
// controller runtime.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}

func sanitiseCertificateRequestSpec(spec *cmapi.CertificateRequestSpec) error {
	// Ensure there is a duration
	if spec.Duration == nil {
		spec.Duration = &metav1.Duration{
			Duration: cmapi.DefaultCertificateDuration,
		}
	}
	// Very short durations should be increased
	if spec.Duration.Duration < cmapi.MinimumCertificateDuration {
		spec.Duration = &metav1.Duration{
			Duration: cmapi.MinimumCertificateDuration,
		}
	}
	if len(spec.Request) == 0 {
		return errors.New("certificate request is empty")
	}
	return nil
}
