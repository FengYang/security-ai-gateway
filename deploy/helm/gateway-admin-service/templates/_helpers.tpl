{{- define "gateway-admin-service.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gateway-admin-service.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "gateway-admin-service.labels" -}}
app: {{ include "gateway-admin-service.name" . }}
app.kubernetes.io/name: {{ include "gateway-admin-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "gateway-admin-service.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "gateway-admin-service.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "gateway-admin-service.jwtSecretName" -}}
{{- if .Values.jwt.existingSecret -}}
{{- .Values.jwt.existingSecret -}}
{{- else -}}
{{- printf "%s-jwt" (include "gateway-admin-service.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "gateway-admin-service.publicBase" -}}
{{- if .Values.broker.publicBase -}}
{{- .Values.broker.publicBase -}}
{{- else -}}
{{- printf "http://%s.%s.svc.cluster.local:%v" (include "gateway-admin-service.fullname" .) .Release.Namespace .Values.broker.port -}}
{{- end -}}
{{- end -}}
