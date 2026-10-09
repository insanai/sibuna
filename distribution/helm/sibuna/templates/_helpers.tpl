{{- define "sibuna.name" -}}
{{- printf "%s-sibuna" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "sibuna.selector" -}}
app.kubernetes.io/name: sibuna
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}
