# Twingate Kubernetes Access Gateway

[![CI](https://github.com/Twingate/kubernetes-access-gateway/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/Twingate/kubernetes-access-gateway/actions/workflows/ci.yaml)
[![Coverage Status](https://coveralls.io/repos/github/Twingate/kubernetes-access-gateway/badge.svg?branch=maaster&t=7BQPrK)](https://coveralls.io/github/Twingate/kubernetes-access-gateway?branch=main)
[![Dockerhub](https://img.shields.io/badge/dockerhub-images-info.svg?logo=Docker)](https://hub.docker.com/r/twingate/kubernetes-access-gateway)

> [!IMPORTANT]
> **Twingate Kubernetes Access is currently in beta.** Sign up for early access at https://www.twingate.com/product/kubernetes-access.

Twingate Kubernetes Access enables secure, zero-trust access to your Kubernetes cluster. It provides a seamless integration between Twingate's secure access platform and your Kubernetes infrastructure, allowing you to manage and control access to your cluster's services through Twingate's security policies.

## Prerequisites

- Kubernetes cluster (1.31+)
- Twingate account setup with a `Remote Network` for the Kubernetes cluster and
 connectors deployed (see the [Twingate Kubernetes Operator](https://github.com/Twingate/kubernetes-operator) or [the Helm chart](https://github.com/Twingate/helm-charts)
 if required)

## Installation

- Install [`asdf`](https://github.com/asdf-vm/asdf) and [`asdf-golang`](https://github.com/asdf-community/asdf-golang). Then run `asdf install` to install the required versions in `.tool-versions`.
- Install [Docker](https://docs.docker.com/get-started/get-docker/) to run KinD
- Install [KinD](https://kind.sigs.k8s.io/docs/user/quick-start#installation) to setup a local Kubernetes cluster
- Install [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl) to interact with the cluster
- Install [helm-unittest](https://github.com/helm-unittest/helm-unittest) plugin for unit-testing Helm chart
  ```
  helm plugin install https://github.com/helm-unittest/helm-unittest.git
  ```

## Testing

### Integration testing

- Integration tests are located in `test/integration` directory. The test would setup [a KinD cluster](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) and use [`kubectl`](https://kubernetes.io/docs/reference/kubectl/kubectl/) CLI to run the tests. Make sure you have Docker runtime so that the KinD cluster can be created automatically.
- Run `make test-integration` to run integration tests.

### Helm testing

- Run `make test-helm` to test changes in Helm chart
- If the test snapshot changes are expected, run `test-helm-and-update-snapshots` to update the snapshots.

### Debugging

You can debug the Gateway locally using Minikube or other Kubernetes environments. The following guide assumes you already have a connector and a gateway deployed in your cluster.

#### Debugging with Minikube

1. **Point Docker to Minikube's Docker Daemon**

   This allows you to build images directly in the Minikube environment:

   ```sh
   eval $(minikube docker-env)
   ```

2. **Build the Debug Image**

   Build a debug-enabled image using the provided Makefile target (make sure you have [goreleaser](https://goreleaser.com/install/) installed):

   ```sh
   make build
   ```

   It will create the `twingate/kubernetes-access-gateway` image with the following tags:
    - `<version>-local-<hash>-linux-arm64`
    - `<version>-local-<hash>-linux-amd64`
    - `<version>-local-<hash>-linux-amd64-debug`
    - `<version>-local-<hash>-linux-arm64-debug`

3. **Update the Gateway Deployment**

   Load the image you want to run to minikube:

   ```sh
     minikube image load <the image:tag to from previous step>
   ```

   Upgrade (or install) the gateway deployment to use your local debug image and enable diagnostic mode (Delve debugger):

   ```sh
   helm upgrade <release-name> ./deploy/gateway/ --install -f <values.yaml> \
     --set image.tag="<one of the tags from previous step>" \
     --set livenessProbe.timeoutSeconds=3600 \
     --set readinessProbe.timeoutSeconds=3600
   ```

   > **Note:** Replace `<release-name>` and `<values.yaml>` with your actual release name and values file.

4. **Port Forward to the Debugger**

   Forward port 2345 from the gateway pod to your local machine:

   ```sh
   kubectl port-forward pod/<gateway-pod> 2345:2345
   ```

5. **Connect Your Debugger**

   Use your Go debugger (e.g., GoLand, VS Code, or Delve CLI) to connect to `127.0.0.1:2345`.

---

### What Happens When Diagnostic Mode Is Enabled?

- The gateway container will start with the Delve debugger in headless mode, listening on port 2345.
- You can set breakpoints and debug the Go process remotely.

---

### Troubleshooting

- If you have trouble connecting, ensure the pod is running and port 2345 is not already in use locally.
- If you see connection errors, double-check that diagnostic mode is enabled and the correct image is deployed.

## Releasing

We use tags to release. `Makefile` has shortcut commands to release development or production releases.
Semantic Release is used to determine the version (see `go tool svu next`).

- `make cut-release`        - release a dev release (ex: `v0.2.1-dev+7a5384c`)
- `make cut-release-prod`   - release a production release (ex: `v0.2.2`)

## Support

- For general issues using this gateway please open a GitHub issue.
- For account specific issues, please visit the [Twingate forum](https://forum.twingate.com/)
 or open a [support ticket](https://help.twingate.com/)
