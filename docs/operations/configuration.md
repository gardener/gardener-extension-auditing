---
title: Configuring the Auditing Extension (Garden)
description: Learn how to enable audit log forwarding for Garden clusters
---

# Configuring the Auditing Extension for Garden Clusters

> [!NOTE]
>
> For Shoot cluster configuration, see the [usage documentation](../usage/configuration.md).

## Garden Configuration

### Enabling the extension

To enable audit log forwarding for a Garden cluster:

1. Configure an [Audit Policy](https://github.com/gardener/gardener/blob/master/docs/usage/security/shoot_auditpolicy.md) for the Garden's virtual cluster `kube-apiserver` and `gardener-apiserver`. Note, the two API servers are handling different APIs respectively each of them has own specific audit policy scoped to the served resources.
2. Add an entry of type `auditing` under `spec.extensions` with a `providerConfig` of kind `AuditConfiguration`

Minimal example:

```yaml
apiVersion: operator.gardener.cloud/v1alpha1
kind: Garden
metadata:
  name: garden
spec:
  extensions:
  - type: auditing
    providerConfig:
      apiVersion: auditing.extensions.gardener.cloud/v1alpha1
      kind: AuditConfiguration
      backends:
      - http:
          url: https://audit-backend.gardener.cloud/audit
          tls:
            secretReferenceName: audit-mtls-creds
  resources:
  - name: audit-mtls-creds
    resourceRef:
      apiVersion: v1
      kind: Secret
      name: mtls-credentials
  virtualCluster:
    kubernetes:
      kubeAPIServer:
        auditConfig:
          auditPolicy:
            configMapRef:
                name: audit-policy
    gardener:
      gardenerAPIServer:
        auditConfig:
          auditPolicy:
            configMapRef:
              name: audit-policy-garden
        # ... other configuration ...
---
apiVersion: v1
kind: Secret
metadata:
  name: mtls-credentials
  namespace: garden
data:
  ca.crt: <base64 PEM encoded CA bundle to validate server certificates> # optional, if not set root CAs will be used
  client.crt: <base64 PEM encoded client certificate>
  client.key: <base64 PEM encoded client key>
```

For full list of options, please consult the [API reference](../api-reference/auditing.md).

For details about the format of audit events sent to backends, see [Audit Event Format](event-format.md).

### Disabling the extension

Remove the `auditing` entry from `spec.extensions`. The extension will clean up deployed resources. (Audit policy remains; you can also remove or adjust it separately.)
