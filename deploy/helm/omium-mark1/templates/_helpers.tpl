{{- /* omium.podSecurityContext / omium.containerSecurityContext / omium.spread: vendored verbatim from Omium-platform/infrastructure/helm/omium-platform/templates/_helpers.tpl (2026-09-17); a chart cannot include another chart's helpers. */ -}}
{{- define "omium.podSecurityContext" -}}
{{- $sec := (default (dict) .root.Values.security) -}}
{{- if ne (toString (default true $sec.enabled)) "false" -}}
{{- $base := (default (dict) $sec.podSecurityContext) -}}
{{- $ovr := (dig .svc "podSecurityContext" (dict) (default (dict) $sec.overrides)) -}}
{{- $merged := mergeOverwrite (deepCopy $base) $ovr -}}
{{- if $merged -}}
securityContext:
{{ toYaml $merged | indent 2 }}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "omium.spread" -}}
{{- $av := (default (dict) .root.Values.availability) -}}
{{- if ne (toString (default true $av.enabled)) "false" -}}
{{- $mode := dig .svc "whenUnsatisfiable" (default "ScheduleAnyway" $av.whenUnsatisfiable) (default (dict) $av.overrides) -}}
topologySpreadConstraints:
- maxSkew: 1
  topologyKey: kubernetes.io/hostname
  whenUnsatisfiable: {{ $mode }}
  labelSelector:
    matchLabels:
      app: {{ .app }}
{{- end -}}
{{- end -}}

{{- define "omium.containerSecurityContext" -}}
{{- $sec := (default (dict) .root.Values.security) -}}
{{- if ne (toString (default true $sec.enabled)) "false" -}}
{{- $base := (default (dict) $sec.containerSecurityContext) -}}
{{- $ovr := (dig .svc "containerSecurityContext" (dict) (default (dict) $sec.overrides)) -}}
{{- $merged := mergeOverwrite (deepCopy $base) $ovr -}}
{{- if $merged -}}
securityContext:
{{ toYaml $merged | indent 2 }}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "mark1.ns" -}}
{{ .Values.global.namespace | default .Release.Namespace }}
{{- end -}}

{{- /* mark1.image: (dict "root" $ "name" "mark1-controld" "tag" .Values.controld.imageTag "key" "controld.imageTag") */ -}}
{{- define "mark1.image" -}}
{{ .root.Values.imageRegistry.url }}/{{ .root.Values.imageRegistry.organization }}/{{ .name }}:{{ required (printf "%s must be a pinned <sha7>; latest is retired estate-wide" .key) .tag }}
{{- end -}}

{{- define "mark1.svcUrl" -}}
http://{{ .name }}.{{ include "mark1.ns" .root }}.svc.cluster.local:{{ .port }}
{{- end -}}

{{- /* mark1.pyPgDsn: the <PREFIX>_PG_DSN a Python service boots on, derived from values + the role's password (secretKeyRef); sslmode pinned. Passwords must be URL-safe (no @ : / ? # %), the SM seed sets that. */ -}}
{{- define "mark1.pyPgDsn" -}}
- name: MARK1_PG_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .root.Values.secrets.dbServiceCredentials }}
      key: {{ .role | quote }}
- name: {{ .prefix }}_PG_DSN
  value: "postgres://{{ .role }}:$(MARK1_PG_PASSWORD)@{{ required "config.postgresql.host is required" .root.Values.config.postgresql.host }}:{{ .root.Values.config.postgresql.port }}/{{ .root.Values.config.postgresql.database }}?sslmode=require"
{{- end -}}

{{- /* mark1.intelEnv / mark1.adjEnv: shared by the Deployment and its CronJobs so the two can never drift. */ -}}
{{- define "mark1.intelEnv" -}}
{{ include "mark1.pyPgDsn" (dict "root" . "role" .Values.intel.postgresRole "prefix" "INTEL") }}
- name: INTEL_QUERYCHOKE_BASE_URL
  value: {{ include "mark1.svcUrl" (dict "root" . "name" "controld" "port" .Values.controld.port) | quote }}
- name: INTEL_ADJUDICATOR_BASE_URL
  value: {{ include "mark1.svcUrl" (dict "root" . "name" "adjudicator" "port" .Values.adjudicator.port) | quote }}
- name: INTEL_QUERYCHOKE_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.serviceToken }}
      key: token
- name: INTEL_TENANT_HMAC_PEPPER
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.hmacPepper }}
      key: pepper
{{- with .Values.config.s3.corpusBucket }}
- name: INTEL_CORPUS_ROOT_URI
  value: "s3://{{ . }}"
{{- end }}
- name: AWS_REGION
  value: {{ .Values.global.region | quote }}
{{- end -}}

{{- define "mark1.adjEnv" -}}
{{ include "mark1.pyPgDsn" (dict "root" . "role" .Values.adjudicator.postgresRole "prefix" "ADJ") }}
- name: ADJ_QUERYCHOKE_BASE_URL
  value: {{ include "mark1.svcUrl" (dict "root" . "name" "controld" "port" .Values.controld.port) | quote }}
- name: ADJ_QUERYCHOKE_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.serviceToken }}
      key: token
- name: ADJ_TENANT_HMAC_PEPPER
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.hmacPepper }}
      key: pepper
- name: AWS_REGION
  value: {{ .Values.global.region | quote }}
{{- end -}}
