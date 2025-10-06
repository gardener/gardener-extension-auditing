---
title: Configuring the Auditing Extension
description: Learn the purpose of the Gardener auditing extension, how to enable it for a Shoot, and how to configure audit log forwarding
---

# Configuring the Auditing Extension

## Shoot Configuration

### Enabling the extension

The extension is not globally enabled and must be configured per Shoot.
- Configure an [Audit Policy](https://github.com/gardener/gardener/blob/master/docs/usage/security/shoot_auditpolicy.md) for the Shoot cluster
- Add an entry of type `auditing` under `spec.extensions` with a `providerConfig` of kind `AuditConfiguration`

Below is a minimal example:

```yaml
apiVersion: core.gardener.cloud/v1beta1
kind: Shoot
metadata:
  name: crazy-botany
  namespace: garden-dev
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
  kubernetes:
    kubeAPIServer:
      auditConfig:
        auditPolicy:
          configMapRef:
            name: audit-policy
    # ... other configuration ...
---
apiVersion: v1
kind: Secret
metadata:
  name: mtls-credentials
  namespace: garden-dev
data:
  ca.crt: <base64 PEM encoded CA bundle to validate server certificates> # optional, if not set root CAs will be used
  client.crt: <base64 PEM encoded client certificate>
  client.key: <base64 PEM encoded client key>
```

For full list of options, please consult the [API reference](../api-reference/auditing.md).

For details about the format of audit events sent to backends, see [Audit Event Format](event-format.md).

### Disabling the extension

Remove the `auditing` entry from `spec.extensions`. The extension will clean up deployed resources. (Audit policy remains; you can also remove or adjust it separately.)
