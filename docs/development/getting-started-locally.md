---
title: Deploying Auditing Extension Locally
description: Learn how to set up a local development environment
---

# Deploying Auditing Extension Locally

## Prerequisites

- Make sure that you have a running local Gardener setup. The steps to complete this can be found in the [Deploying Gardener Locally guide](https://github.com/gardener/gardener/blob/master/docs/deployment/getting_started_locally.md).

## Setting up the Auditing Extension

Make sure that your `KUBECONFIG` environment variable is targeting the local Gardener cluster. When this is ensured, run:

```bash
make extension-up
```

The corresponding make target will build the extension image, load it into the kind cluster Nodes, and deploy the auditing ControllerDeployment and ControllerRegistration resources. The container image in the ControllerDeployment will be the image that was build and loaded into the kind cluster Nodes.

In addition to than an echo server will be deployed in its own Namespace which can be used as a dummy auditlogging backend.

The make target will then deploy the auditing admission component. It will build the admission image, load it into the kind cluster Nodes, and finally install the admission component charts to the kind cluster.

## Creating a Shoot Cluster

1. Deploy an auditing policy.

[`example/local-setup/policy.yaml`](../../example/local-setup/policy.yaml) contains a Policy specification:
```bash
kubectl create -f example/local-setup/policy.yaml
```

2. Create a Shoot cluster.

[`example/local-setup/shoot.yaml`](../../example/local-setup/shoot.yaml) contains a Shoot specification with the `auditing` extension:
```bash
kubectl create -f example/local-setup/shoot.yaml
```

3. Once the Shoot namespace is created in the seed cluster create a NetworkPolicy which will allow traffic from the auditlog forwarder to the echo server.
[`example/local-setup/netpol.yaml`](../../example/local-setup/netpol.yaml) contains a NetworkPolicy allowing communication between the auditlog forwarder and the echo server:
```bash
kubectl create -f example/local-setup/netpol.yaml
```
