---
title: Deploying Auditing Extension Locally
description: Learn how to set up a local development environment
---

# Deploying Auditing Extension Locally

## Setup without Gardener Operator

### Prerequisites

- Make sure that you have a running local Gardener setup. The steps to complete this can be found in the [Deploying Gardener Locally guide](https://github.com/gardener/gardener/blob/master/docs/deployment/getting_started_locally.md).

### Setting up the Auditing Extension

Make sure that your `KUBECONFIG` environment variable is targeting the local Gardener cluster. When this is ensured, run:

```bash
make extension-up
```

The corresponding make target will build the extension image, load it into the kind cluster Nodes, and deploy the auditing ControllerDeployment and ControllerRegistration resources. The container image in the ControllerDeployment will be the image that was build and loaded into the kind cluster Nodes.

In addition to than an echo server will be deployed in its own Namespace which can be used as a dummy auditlogging backend.

The make target will then deploy the auditing admission component. It will build the admission image, load it into the kind cluster Nodes, and finally install the admission component charts to the kind cluster.

### Creating a Shoot Cluster

1. Create a secret containing the credentials used for mTLS.

```bash
kubectl -n garden-local create secret generic echo-server-creds \
    --from-file=ca.crt=example/local-setup/dev/certs/ca.crt \
    --from-file=client.crt=example/local-setup/dev/certs/client.crt \
    --from-file=client.key=example/local-setup/dev/certs/client.key
```

2. Deploy an auditing policy.

[`example/local-setup/policy.yaml`](../../example/local-setup/policy.yaml) contains a Policy specification:
```bash
kubectl apply -f example/local-setup/policy.yaml
```

3. Create a Shoot cluster.

[`example/local-setup/shoot.yaml`](../../example/local-setup/shoot.yaml) contains a Shoot specification with the `auditing` extension:
```bash
kubectl apply -f example/local-setup/shoot.yaml
```

4. Once the Shoot namespace is created in the seed cluster create a NetworkPolicy which will allow traffic from the auditlog forwarder to the echo server.
[`example/local-setup/netpol.yaml`](../../example/local-setup/netpol.yaml) contains a NetworkPolicy allowing communication between the auditlog forwarder and the echo server:
```bash
kubectl apply -f example/local-setup/netpol.yaml
```

## Setup with Gardener Operator

Alternatively, you can deploy the auditing extension in the `gardener-operator` local setup. To do this, make sure you are have a running local setup based on [Alternative Way to Set Up Garden and Seed Leveraging `gardener-operator`](https://github.com/gardener/gardener/blob/master/docs/deployment/getting_started_locally.md#alternative-way-to-set-up-garden-and-seed-leveraging-gardener-operator). The `KUBECONFIG` environment variable should target the operator local KinD cluster (i.e. `<path_to_gardener_project>/example/gardener-local/kind/multi-zone/kubeconfig`).

```bash
export KUBECONFIG=$(pwd)/../gardener/example/gardener-local/kind/multi-zone/kubeconfig
```

### Creating the auditing `Extension.operator.gardener.cloud` resource:

```bash
make extension-operator-up
```

The corresponding make target will build the auditing admission and extension container images, OCI artifacts for the admission runtime and application charts, and the extension chart. Then, the container images and the OCI artifacts are pushed into the default skaffold registry (i.e. `garden.local.gardener.cloud:5001`). Next, the auditing `Extension.operator.gardener.cloud` resource is deployed into the KinD cluster. Based on this resource the gardener-operator will deploy the auditing admission component, as well as the auditing ControllerDeployment and ControllerRegistration resources.

### Creating a Shoot Cluster

1. Target the Garden cluster.

```bash
export KUBECONFIG=$(pwd)/../gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig
```

2. Create a secret containing the credentials used for mTLS.

```bash
kubectl -n garden-local create secret generic echo-server-creds \
    --from-file=ca.crt=example/local-setup/dev/certs/ca.crt \
    --from-file=client.crt=example/local-setup/dev/certs/client.crt \
    --from-file=client.key=example/local-setup/dev/certs/client.key
```

3. Deploy an auditing policy.

[`example/local-setup/policy.yaml`](../../example/local-setup/policy.yaml) contains a Policy specification:
```bash
kubectl apply -f example/local-setup/policy.yaml
```

4. Create a Shoot cluster.

[`example/local-setup/shoot.yaml`](../../example/local-setup/shoot.yaml) contains a Shoot specification with the `auditing` extension:
```bash
kubectl apply -f example/local-setup/shoot.yaml
```

5. Once the Shoot namespace is created in the seed cluster create a NetworkPolicy which will allow traffic from the auditlog forwarder to the echo server.
[`example/local-setup/netpol.yaml`](../../example/local-setup/netpol.yaml) contains a NetworkPolicy allowing communication between the auditlog forwarder and the echo server:
```bash
kubectl --kubeconfig $(pwd)/../gardener/example/gardener-local/kind/multi-zone/kubeconfig apply -f example/local-setup/netpol.yaml
```

### Delete the auditing `Extension.operator.gardener.cloud` resource

Delete any shoots using the extension.
```bash
kubectl -n garden-local annotate shoot local confirmation.gardener.cloud/deletion=true
kubectl -n garden-local delete shoot local
```

Make sure the environment variable `KUBECONFIG` points to the operator's local KinD cluster and then run:
```bash
make extension-operator-down
```

The corresponding make target will delete the `Extension.operator.gardener.cloud` resource. Consequently, the gardener-operator will delete the auditing admission component and auditing ControllerDeployment and ControllerRegistration resources.

Finally delete the `ValidatingWebhookConfiguration` from the Virtual Garden cluster.

```bash
kubectl --kubeconfig $(pwd)/../gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig delete validatingwebhookconfiguration gardener-extension-auditing-admission --ignore-not-found
```
