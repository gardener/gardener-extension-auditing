{{- define "name" -}}
{{- if .Values.gardener.runtimeCluster.enabled -}}
gardener-extension-auditing-runtime
{{- else -}}
gardener-extension-auditing
{{- end -}}
{{- end -}}

{{- define "config" -}}
apiVersion: config.auditing.extensions.gardener.cloud/v1alpha1
kind: Configuration
{{- end }}

{{- define "leaderelectionid" -}}
extension-auditing-leader-election
{{- end -}}

{{-  define "image" -}}
  {{- if .Values.image.ref -}}
  {{ .Values.image.ref }}
  {{- else -}}
  {{- if hasPrefix "sha256:" .Values.image.tag }}
  {{- printf "%s@%s" .Values.image.repository .Values.image.tag }}
  {{- else }}
  {{- printf "%s:%s" .Values.image.repository .Values.image.tag }}
  {{- end }}
  {{- end }}
{{- end }}
