# google-cas-issuer

<!-- see https://artifacthub.io/packages/helm/cert-manager/cert-manager-google-cas-issuer for the rendered version -->

## Helm Values

<!-- AUTO-GENERATED -->

#### **crds.enabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```

This option decides if the CRDs should be installed as part of the Helm installation.
#### **crds.keep** ~ `bool`
> Default value:
> ```yaml
> true
> ```

This option makes it so that the "helm.sh/resource-policy": keep annotation is added to the CRD. This will prevent Helm from uninstalling the CRD when the Helm release is uninstalled. WARNING: when the CRDs are removed, all cert-manager custom resources  
(Certificates, Issuers, ...) will be removed too by the garbage collector.
#### **replicaCount** ~ `number`
> Default value:
> ```yaml
> 1
> ```

Number of replicas of google-cas-issuer to run.
#### **image.repository** ~ `string`
> Default value:
> ```yaml
> quay.io/jetstack/cert-manager-google-cas-issuer
> ```

Target image repository.
#### **image.registry** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

Target image registry. Will be prepended to the target image repositry if set.
#### **image.tag** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

Target image version tag. Defaults to the chart's appVersion.
#### **image.digest** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

Target image digest. Will override any tag if set. for example:

```yaml
digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```
#### **image.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

Kubernetes imagePullPolicy on Deployment.
#### **imagePullSecrets** ~ `array`
> Default value:
> ```yaml
> []
> ```

Optional secrets used for pulling the google-cas-issuer container image.
#### **commonLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Labels to apply to all resources
#### **serviceAccount.annotations** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional annotations to add to the service account
#### **app.logLevel** ~ `number`
> Default value:
> ```yaml
> 1
> ```

Verbosity of google-cas-issuer logging.
#### **app.approval.enabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```

enabled determines whether the ClusterRole and ClusterRoleBinding for approval is created. You will want to disable this if you are managing approval RBAC elsewhere from this chart, for example if you create them separately for all installed issuers.
#### **app.approval.subjects[0].kind** ~ `string`
> Default value:
> ```yaml
> ServiceAccount
> ```
#### **app.approval.subjects[0].name** ~ `string`
> Default value:
> ```yaml
> cert-manager
> ```
#### **app.approval.subjects[0].namespace** ~ `string`
> Default value:
> ```yaml
> cert-manager
> ```
#### **app.metrics.port** ~ `number`
> Default value:
> ```yaml
> 9402
> ```

Port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'.
#### **deploymentAnnotations** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional additional annotations to add to the google-cas-issuer Deployment
#### **podAnnotations** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional additional annotations to add to the google-cas-issuer Pods
#### **podLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional additional labels to add to the google-cas-issuer Pods
#### **resources** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Kubernetes pod resource requests/limits for google-cas-issuer.  
For example:

```yaml
limits:
  cpu: 100m
  memory: 128Mi
requests:
  cpu: 100m
  memory: 128Mi
```
#### **nodeSelector** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Kubernetes node selector: node labels for pod assignment  
For example:

```yaml
kubernetes.io/os: linux
```
#### **affinity** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Kubernetes affinity: constraints for pod assignment  
For example:

```yaml
nodeAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    nodeSelectorTerms:
    - matchExpressions:
      - key: foo.bar.com/role
        operator: In
        values:
        - master
```
#### **tolerations** ~ `array`
> Default value:
> ```yaml
> []
> ```

Kubernetes pod tolerations for google-cas-issuer  
For example:  
 - operator: "Exists"
#### **priorityClassName** ~ `string`
> Default value:
> ```yaml
> ""
> ```

Optional priority class to be used for the google-cas-issuer pods.

<!-- /AUTO-GENERATED -->