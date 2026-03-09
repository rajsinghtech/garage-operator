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
{{- $tag := default .Chart.AppVersion .Values.image.tag }}
{{- printf "%s:%s" .Values.image.repository $tag }}
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
{{- $namespaces | join "," -}}
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
