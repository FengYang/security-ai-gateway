{{- define "otpmask.namespace" -}}
{{- .Values.namespace | default "otpmask" -}}
{{- end -}}

{{- define "otpmask.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "otpmask.labels" -}}
app.kubernetes.io/part-of: otpmask
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

