---
title: Configuring the Auditing Extension
description: Learn the purpose of the Gardener auditing extension, how to enable it for a Shoot, and how to configure audit log forwarding
---

# Configuring the Auditing Extension

## Introduction

### Use Case

Kubernetes audit logs are essential for security investigations, compliance evidence, and operational troubleshooting. Long‑term storage, external analysis, SIEM ingestion, or near real‑time alerting requires that these audit events leave the cluster boundary in a reliable and secure way.

The Gardener auditing extension (type `auditing`) deploys and manages the [auditlog-forwarder](https://github.com/gardener/auditlog-forwarder) inside the control plane of a Shoot cluster. This webhook component receives the API server audit logs, enriches them with Gardener specific metadata and forwards the events to one or more remote backends.

### Solution Overview

1. You configure an audit policy for the Shoot's kube-apiserver (via `spec.kubernetes.kubeAPIServer.auditConfig.auditPolicy`).
2. You enable the auditing extension on the Shoot and provide a list of forwarding backends in `providerConfig`.
3. The extension reconciler deploys the `auditlog-forwarder` Deployment plus supporting objects (ServiceAccount, RBAC, VPA, etc.) into the Shoot namespace in the Seed cluster.
4. The forwarder receives the audit events from the kube-apiserver (sent over HTTPS on a webhook endpoint), enriches them with Gardener specific metadata and sends them to the configured remote endpoints.

### Data Flow

kube-apiserver -> auditlog-forwarder -> External receiver(s)

### Features

* Multiple backends (fan‑out) – each event is attempted to be delivered to all configured backends. (this function is currently limited to a single backend)
* HTTPS delivery via mutual TLS.

> ![NOTE]
> Current API focuses on HTTP(S) backends. Future versions may add additional backend types (e.g. OTLP).

## Shoot Configuration

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
apiVersion: "v1"
kind: Secret
metadata:
  name: mtls-credentials
  namespace: garden-dev
data:
  ca.crt: <PEM encoded CA bundle to validate server certificates> # optional, if not set root CAs will be used
  client.crt: <base64 PEM encoded client certificate>
  client.key: <base64 PEM encoded client key>
```

For full list of options, please consult the [API reference](../api-reference/auditing.md).

### Disabling the extension

Remove the `auditing` entry from `spec.extensions`. The extension will clean up deployed resources. (Audit policy remains; you can also remove or adjust it separately.)


