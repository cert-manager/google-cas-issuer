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
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"

	"github.com/go-logr/logr"
	cmutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	api "github.com/jetstack/google-cas-issuer/api/v1alpha1"
	"github.com/jetstack/google-cas-issuer/pkg/cas"
	issuerctrl "github.com/jetstack/google-cas-issuer/pkg/controller/issuer"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	casapi "github.com/jetstack/google-cas-issuer/api/v1alpha1"
)

// CertificateRequestReconciler reconciles CSRs
type CertificateRequestReconciler struct {
	client.Client
	Log logr.Logger
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
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

	var googleCASClient cas.Client
	var parent string

	switch certificateRequest.Spec.IssuerRef.Kind {
	case "GoogleCASClusterIssuer":
		issuer := api.GoogleCASClusterIssuer{}
		issuerNamespaceName := types.NamespacedName{
			Name: certificateRequest.Spec.IssuerRef.Name,
		}
		if err := r.Client.Get(ctx, issuerNamespaceName, &issuer); err != nil {
			log.Error(err, "failed to retrieve GoogleCASClusterIssuer resource", "namespace", req.Namespace, "name", certificateRequest.Spec.IssuerRef.Name)
			return ctrl.Result{}, err
		}
		parent = fmt.Sprintf("projects/%s/locations/%s/certificateAuthorities/%s", issuer.Spec.Project, issuer.Spec.Location, issuer.Spec.CertificateAuthorityID)
		casClient, ok := issuerctrl.ClusterIssuers.Load(issuerNamespaceName)
		if !ok {
			err := errors.New("couldn't retrieve CAS ClusterIssuer client - it probably hasn't reconciled yet")
			log.Error(err, err.Error(), "namespace", req.Namespace, "name", certificateRequest.Spec.IssuerRef.Name)
			return ctrl.Result{}, err
		}
		googleCASClient, ok = casClient.(cas.Client)
		if !ok {
			err := errors.New("Retrieved a non-CAS client from the cache, this should never happen")
			log.Error(err, err.Error(), "namespace", req.Namespace, "name", certificateRequest.Spec.IssuerRef.Name)
			return ctrl.Result{}, err
		}
	case "GoogleCASIssuer":
		issuer := api.GoogleCASIssuer{}
		issuerNamespaceName := types.NamespacedName{
			Namespace: req.Namespace,
			Name:      certificateRequest.Spec.IssuerRef.Name,
		}
		if err := r.Client.Get(ctx, issuerNamespaceName, &issuer); err != nil {
			return ctrl.Result{}, err
		}
		parent = fmt.Sprintf("projects/%s/locations/%s/certificateAuthorities/%s", issuer.Spec.Project, issuer.Spec.Location, issuer.Spec.CertificateAuthorityID)
		casClient, ok := issuerctrl.Issuers.Load(issuerNamespaceName)
		if !ok {
			err := errors.New("couldn't retrieve CAS Issuer client - it probably hasn't reconciled yet")
			log.Error(err, err.Error(), "namespace", req.Namespace, "name", certificateRequest.Spec.IssuerRef.Name)
			return ctrl.Result{}, err
		}
		googleCASClient, ok = casClient.(cas.Client)
		if !ok {
			err := errors.New("Retrieved a non-CAS client from the cache, this should never happen")
			log.Error(err, err.Error(), "namespace", req.Namespace, "name", certificateRequest.Spec.IssuerRef.Name)
			return ctrl.Result{}, err
		}
	default:
		log.Info("Noticed unhandled kind in Certificate Request:", "kind", certificateRequest.Spec.IssuerRef.Kind)
		return ctrl.Result{}, nil
	}

	// Issue cert here
	opts := &cas.CreateCertificateOptions{
		Parent:        parent,
		CertificateID: fmt.Sprintf("cert-manager-%d", rand.Int()),
		CSR:           certificateRequest.Spec.Request,
		Expiry:        certificateRequest.Spec.Duration.Duration,
	}

	cert, chain, err := googleCASClient.CreateCertificate(opts)
	if err != nil {
		log.Error(err, "Couldn't sign certificate", "namespace", req.Namespace, "name", certificateRequest.Name, "err", err)
		return ctrl.Result{}, err
	}

	certbuf := &bytes.Buffer{}
	certbuf.WriteString(cert)
	for _, c := range chain[:len(chain)-1] {
		certbuf.WriteString(c)
	}
	certificateRequest.Status.Certificate = certbuf.Bytes()
	certificateRequest.Status.CA = []byte(chain[len(chain)-1])

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
