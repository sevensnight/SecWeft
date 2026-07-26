{{- define "vulnlab.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "vulnlab.fullname" -}}
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

{{- define "vulnlab.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app.kubernetes.io/name: {{ include "vulnlab.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: vulnlab-platform
{{- end }}

{{- define "vulnlab.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vulnlab.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "vulnlab.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vulnlab.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "vulnlab.secretName" -}}
{{- if .Values.runtimeSecrets.existingSecret }}
{{- .Values.runtimeSecrets.existingSecret }}
{{- else if .Values.secrets.create }}
{{- printf "%s-runtime" (include "vulnlab.fullname" .) }}
{{- else }}
{{- required "runtimeSecrets.existingSecret or secrets.existingSecret is required" .Values.secrets.existingSecret }}
{{- end }}
{{- end }}
