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

package controllers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/go-logr/logr"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	api "github.com/jetstack/google-cas-issuer/api/v1alpha1"
	"github.com/jetstack/google-cas-issuer/util/cas"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"math/rand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertificateRequestReconciler reconciles CSRs
type CertificateRequestReconciler struct {
	client.Client
	Log      logr.Logger
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch

func (r *CertificateRequestReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("certificaterequest", req.NamespacedName)

	// Fetch the CertificateRequest resource being reconciled.
	// Just ignore the request if the certificate request has been deleted.
	cr := new(cmapi.CertificateRequest)
	if err := r.Client.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		log.Error(err, "failed to retrieve CertificateRequest resource")
		return ctrl.Result{}, err
	}

	// Check the CertificateRequest's issuerRef and if it does not match the api
	// group name, log a message at a debug level and stop processing.
	if cr.Spec.IssuerRef.Group != "" && cr.Spec.IssuerRef.Group != api.GroupVersion.Group {
		log.V(4).Info("resource does not specify an issuerRef group name that we are responsible for", "group", cr.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// If the certificate data is already set then we skip this request as it
	// has already been completed in the past.
	if len(cr.Status.Certificate) > 0 {
		log.V(4).Info("existing certificate data found in status, skipping already completed CertificateRequest")
		return ctrl.Result{}, nil
	}
	var issuerNamespaceName types.NamespacedName
	var casClient interface{}
	var ok bool
	var parent string
	if cr.Spec.IssuerRef.Kind == "GoogleCASClusterIssuer" {
		issuer := api.GoogleCASClusterIssuer{}
		issuerNamespaceName = types.NamespacedName{
			Name: cr.Spec.IssuerRef.Name,
		}
		if err := r.Client.Get(ctx, issuerNamespaceName, &issuer); err != nil {
			log.Error(err, "failed to retrieve GoogleCASClusterIssuer resource", "namespace", req.Namespace, "name", cr.Spec.IssuerRef.Name)
			_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to retrieve CAS Issuer resource %s: %v", issuerNamespaceName, err)
			return ctrl.Result{}, err
		}
		parent = fmt.Sprintf("projects/%s/locations/%s/certificateAuthorities/%s", issuer.Spec.Project, issuer.Spec.Location, issuer.Spec.CertificateAuthorityID)
		casClient, ok = ClusterIssuers.Load(issuerNamespaceName)
	} else if cr.Spec.IssuerRef.Kind == "GoogleCASIssuer" {
		issuer := api.GoogleCASIssuer{}
		issuerNamespaceName = types.NamespacedName{
			Namespace: req.Namespace,
			Name:      cr.Spec.IssuerRef.Name,
		}
		if err := r.Client.Get(ctx, issuerNamespaceName, &issuer); err != nil {
			log.Error(err, "failed to retrieve GoogleCASClusterIssuer resource", "namespace", req.Namespace, "name", cr.Spec.IssuerRef.Name)
			_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to retrieve CAS Issuer resource %s: %v", issuerNamespaceName, err)
			return ctrl.Result{}, err
		}
		parent = fmt.Sprintf("projects/%s/locations/%s/certificateAuthorities/%s", issuer.Spec.Project, issuer.Spec.Location, issuer.Spec.CertificateAuthorityID)
		casClient, ok = Issuers.Load(issuerNamespaceName)
	} else {
		log.Info("Noticed unhandled kind in Certificate Request:", "kind", cr.Spec.IssuerRef.Kind)
		return ctrl.Result{}, nil
	}
	// Issue cert here
	opts := &cas.CreateCertificateOptions{
		Parent: parent,
		//CertificateID: issuer.Spec.CertificateAuthorityID,
		CertificateID: fmt.Sprintf("cert-manager-%d", rand.Int()),
		CSR:           cr.Spec.Request,
		Expiry:        cr.Spec.Duration.Duration,
	}

	if !ok {
		e := errors.New("couldn't retrieve CAS Issuer client - it probably hasn't reconciled yet")
		log.Error(e, e.Error(), "namespace", req.Namespace, "name", cr.Spec.IssuerRef.Name)
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Couldn't retrieve CAS Issuer client %s: %v", issuerNamespaceName, errors.New("couldn't retrieve CAS Issuer client"))
		return ctrl.Result{}, e
	}
	googleCASClient, ok := casClient.(cas.Client)

	if !ok {
		e := errors.New("Retrieved a non-CAS client from the cache, this should never happen")
		log.Error(e, e.Error(), "namespace", req.Namespace, "name", cr.Spec.IssuerRef.Name)
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Couldn't retrieve CAS Issuer client %s: %v", issuerNamespaceName, errors.New("couldn't retrieve CAS Issuer client"))
		return ctrl.Result{}, e
	}
	cert, chain, err := googleCASClient.CreateCertificate(opts)
	if err != nil {
		log.Error(err, "Couldn't sign certificate", "namespace", req.Namespace, "name", cr.Name, "err", err)
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Couldn't sign certificate %s: %v", cr.Name, err)
		return ctrl.Result{}, err
	}
	cr.Status.Certificate = []byte(cert)
	buf := &bytes.Buffer{}
	for _, c := range chain {
		buf.WriteString(c)
	}
	cr.Status.CA = buf.Bytes()
	return ctrl.Result{}, r.setStatus(ctx, cr, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Certificate issued")
}

func (r *CertificateRequestReconciler) setStatus(ctx context.Context, cr *cmapi.CertificateRequest, status cmmeta.ConditionStatus, reason, message string, args ...interface{}) error {
	completeMessage := fmt.Sprintf(message, args...)
	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, status, reason, completeMessage)

	// Fire an Event to additionally inform users of the change
	eventType := core.EventTypeNormal
	if status == cmmeta.ConditionFalse {
		eventType = core.EventTypeWarning
	}
	r.Recorder.Event(cr, eventType, reason, completeMessage)

	return r.Client.Status().Update(ctx, cr)
}

// SetupWithManager initializes the CertificateRequest controller into the
// controller runtime.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
