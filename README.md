# [Gardener Extension Auditing](https://gardener.cloud)

[![Build](https://github.com/gardener/gardener-extension-auditing/actions/workflows/non-release.yaml/badge.svg)](https://github.com/gardener/gardener-extension-auditing/actions/workflows/non-release.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/gardener/gardener-extension-auditing)](https://goreportcard.com/report/github.com/gardener/gardener-extension-auditing)
[![REUSE status](https://api.reuse.software/badge/github.com/gardener/gardener-extension-auditing)](https://api.reuse.software/info/github.com/gardener/gardener-extension-auditing)

## Introduction

Gardener extension controller which deploys an auditlog forwarder sending Audit Events to configured backends.

### Use Case

Kubernetes audit logs are essential for security investigations, compliance evidence, and operational troubleshooting. Long‑term storage, external analysis, SIEM ingestion, or near real‑time alerting requires that these audit events leave the cluster boundary in a reliable and secure way.

The Gardener auditing extension (type `auditing`) deploys and manages the [auditlog-forwarder](https://github.com/gardener/auditlog-forwarder) inside the control plane of a Shoot cluster. This webhook component receives the API server audit logs, enriches them with Gardener specific metadata and forwards the events to one or more remote backends.

### Solution Overview

1. You configure an audit policy for the Shoot's kube-apiserver (via `spec.kubernetes.kubeAPIServer.auditConfig.auditPolicy`).
2. You enable the auditing extension on the Shoot and provide a list of forwarding backends in `providerConfig`.
3. The extension reconciler deploys the `auditlog-forwarder` Deployment plus supporting objects (ServiceAccount, RBAC, VPA, etc.) into the Shoot namespace in the Seed cluster.
4. The forwarder receives audit events from the kube-apiserver (sent over HTTPS on a webhook endpoint), enriches them with Gardener specific metadata and sends them to the configured remote endpoints.

### Data Flow

kube-apiserver -> auditlog-forwarder -> external receiver(s)

### Features

* Multiple backends (fan‑out) – each event is attempted to be delivered to all configured backends. (this function is currently limited to a single backend)
* HTTPS delivery via mutual TLS.

> [!NOTE]
> Current API focuses on HTTP(S) backends. Future versions may add additional backend types (e.g. OTLP).

## Usage

- [Configuring the Auditing Extension](docs/usage/configuration.md) - learn how to enable and configure the auditing extension

## Local Setup and Development

- [Deploying Auditing Extension Locally](docs/development/getting-started-locally.md) - learn how to set up a local development environment

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.
