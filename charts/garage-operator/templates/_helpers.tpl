{{/*
Expand the name of the chart.
*/}}
{{- define "garage-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "garage-operator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "garage-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "garage-operator.labels" -}}
helm.sh/chart: {{ include "garage-operator.chart" . }}
{{ include "garage-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "garage-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "garage-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
control-plane: controller-manager
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "garage-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "garage-operator.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name for the manager ClusterRole
*/}}
{{- define "garage-operator.managerRoleName" -}}
{{- printf "%s-manager-role" (include "garage-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the leader election Role
*/}}
{{- define "garage-operator.leaderElectionRoleName" -}}
{{- printf "%s-leader-election-role" (include "garage-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the metrics auth ClusterRole
*/}}
{{- define "garage-operator.metricsAuthRoleName" -}}
{{- printf "%s-metrics-auth-role" (include "garage-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the metrics reader ClusterRole
*/}}
{{- define "garage-operator.metricsReaderRoleName" -}}
{{- printf "%s-metrics-reader" (include "garage-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the metrics service
*/}}
{{- define "garage-operator.metricsServiceName" -}}
{{- printf "%s-metrics" (include "garage-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the webhook service
*/}}
{{- define "garage-operator.webhookServiceName" -}}
{{- printf "%s-webhook" (include "garage-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the webhook certificate
*/}}
{{- define "garage-operator.webhookCertName" -}}
{{- printf "%s-webhook-cert" (include "garage-operator.fullname" .) }}
{{- end }}

{{/*
Webhook service DNS name
*/}}
{{- define "garage-operator.webhookServiceDNS" -}}
{{- printf "%s.%s.svc" (include "garage-operator.webhookServiceName" .) .Release.Namespace }}
{{- end }}

{{/*
Container image
*/}}
{{- define "garage-operator.image" -}}
{{- $digest := default "" .Values.image.digest }}
{{- if $digest }}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $digest) }}
{{- fail "image.digest must be a lowercase sha256:<64 hexadecimal characters> digest" }}
{{- end }}
{{- printf "%s@%s" .Values.image.repository $digest }}
{{- else }}
{{- $tag := default .Chart.AppVersion .Values.image.tag }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
{{- end }}

{{/*
Whether the operator is namespace-scoped (watchNamespaces is set and watchAnyNamespace is false)
*/}}
{{- define "garage-operator.isNamespaceScoped" -}}
{{- if and .Values.watchNamespaces (not .Values.watchAnyNamespace) -}}
true
{{- end -}}
{{- end }}

{{/*
Build the list of watched namespaces (always includes the release namespace)
*/}}
{{- define "garage-operator.watchedNamespaces" -}}
{{- $namespaces := list .Release.Namespace -}}
{{- range .Values.watchNamespaces -}}
{{- if ne . $.Release.Namespace -}}
{{- $namespaces = append $namespaces . -}}
{{- end -}}
{{- end -}}
{{- if and .Values.cosi.enabled .Values.cosi.namespace (ne .Values.cosi.namespace .Release.Namespace) -}}
{{- $namespaces = append $namespaces .Values.cosi.namespace -}}
{{- end -}}
{{- $namespaces | uniq | join "," -}}
{{- end }}

{{/*
WATCH_NAMESPACE env value: comma-separated namespaces or empty for all
*/}}
{{- define "garage-operator.watchNamespaceEnv" -}}
{{- if .Values.watchAnyNamespace -}}
{{- else if .Values.watchNamespaces -}}
{{- include "garage-operator.watchedNamespaces" . -}}
{{- end -}}
{{- end }}

{{/*
TCP port on which the manager listens for metrics. The Service may expose a
different port, but its named targetPort and the NetworkPolicy must use this
listener port.
*/}}
{{- define "garage-operator.metricsPort" -}}
{{- $address := trim .Values.metrics.bindAddress -}}
{{- if not (regexMatch `^(?:|0\.0\.0\.0|\[::\]):[0-9]+$` $address) -}}
{{- fail "metrics.bindAddress must be a wildcard TCP address such as :8443, 0.0.0.0:8443, or [::]:8443" -}}
{{- end -}}
{{- $portText := regexFind `[0-9]+$` $address -}}
{{- $port := int $portText -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail "metrics.bindAddress port must be between 1 and 65535" -}}
{{- end -}}
{{- $port -}}
{{- end }}

{{/* Prevent the operator metrics from being scraped through both monitor types. */}}
{{- define "garage-operator.monitoringValidation" -}}
{{- if and .Values.serviceMonitor.enabled .Values.podMonitor.enabled -}}
{{- fail "serviceMonitor.enabled and podMonitor.enabled cannot both be true: ServiceMonitor and PodMonitor would double-scrape the operator metrics" -}}
{{- end }}
{{- end }}

{{/* Namespace selector shared by every namespaced admission webhook. */}}
{{- define "garage-operator.webhookNamespaceSelector" -}}
{{- if include "garage-operator.isNamespaceScoped" . }}
namespaceSelector:
  matchExpressions:
  - key: kubernetes.io/metadata.name
    operator: In
    values:
    {{- range (splitList "," (include "garage-operator.watchedNamespaces" .)) }}
    - {{ . | quote }}
    {{- end }}
{{- end }}
{{- end }}
