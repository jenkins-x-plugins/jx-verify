{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "verifyJob.name" -}}
{{- $name := default "gc-jobs" .Values.verifyJob.nameOverride -}}
{{- printf "%s-%s-%s" .Chart.Name $name (lower (randAlphaNum 5)) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "verifyJob.saName" -}}
{{- $name := default "gc-jobs" .Values.verifyJob.nameOverride -}}
{{- printf "%s-%s" .Chart.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
